"""Command line interface: penmunshi doctor | analyze | eval | scan | redact | serve | import | retest | export-demo"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import Settings
from .llm import LLM, FakeLLM, OllamaLLM


def make_llm(backend: str, model: str | None = None) -> LLM:
    if backend == "fake":
        return FakeLLM()
    if backend == "ollama":
        return OllamaLLM(Settings.from_env(), model=model)
    raise SystemExit(f"unknown backend: {backend}")


# ---------------------------------------------------------------- doctor
def _gpu_line() -> str:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return "no NVIDIA GPU tooling found (nvidia-smi missing): Ollama will use the CPU"
    try:
        out = subprocess.run(
            [exe, "--query-gpu=name,memory.total,memory.used", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout.strip()
        return out or "nvidia-smi returned nothing"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"nvidia-smi failed: {exc}"


def cmd_doctor(args: argparse.Namespace) -> int:
    s = Settings.from_env()
    print(f"PenMunshi {__version__}")
    print(f"Ollama URL : {s.ollama_url}")
    print(f"Model      : {args.model or s.model}")
    print(f"GPU        : {_gpu_line()}")
    health = OllamaLLM(s, model=args.model).health()
    if not health["reachable"]:
        print(f"[FAIL] Ollama is not reachable ({health.get('error', 'unknown error')}).")
        print("       Start it with `ollama serve` (or open the Ollama app) and run doctor again.")
        return 1
    print(f"[ OK ] Ollama reachable; {len(health.get('installed', []))} model(s) installed")
    if not health["model_present"]:
        print(f"[FAIL] model '{health['model']}' is not installed. Run: ollama pull {health['model']}")
        return 1
    print(f"[ OK ] model '{health['model']}' is installed")
    print("Next: penmunshi analyze examples/acme-demo --out out/demo")
    return 0


# ---------------------------------------------------------------- analyze
def cmd_analyze(args: argparse.Namespace) -> int:
    from .pipeline import analyze_engagement
    from .report import render_docx, render_html, render_markdown

    llm = make_llm(args.backend, args.model)
    health = llm.health()
    if not health.get("reachable", False):
        print("Model backend is not reachable. Run `penmunshi doctor`.", file=sys.stderr)
        return 1
    report = analyze_engagement(Path(args.engagement), llm, progress=print)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    formats = {f.strip() for f in args.formats.split(",")}
    if "json" in formats:
        (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if "md" in formats:
        (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    if "html" in formats:
        (out / "report.html").write_text(render_html(report), encoding="utf-8")
    if "docx" in formats:
        render_docx(report, out / "report.docx")
    ready = sum(f.status == "ready" for f in report.findings)
    print(f"\n{len(report.findings)} finding(s), {ready} ready, {len(report.findings) - ready} need review")
    for f in report.findings:
        print(f"  {f.severity:9s} {f.cvss_score if f.cvss_score is not None else '-':>4}  [{f.status}] {f.id}")
    print(f"Output written to {out}/")
    return 0


# ---------------------------------------------------------------- eval
def cmd_eval(args: argparse.Namespace) -> int:
    from .eval import load_cases, render_eval_markdown, run_eval
    from .eval.harness import log_heldout_run, report_to_json

    cases = load_cases(Path(args.cases) if args.cases else None)
    if args.backend == "ollama":
        health = OllamaLLM(Settings.from_env(), model=args.model).health()
        if not health["reachable"] or not health["model_present"]:
            print("Ollama/model not ready. Run `penmunshi doctor`.", file=sys.stderr)
            return 1
    report = run_eval(
        cases,
        backend=args.backend,
        model=args.model,
        split=args.split,
        inject_faults=not args.no_faults,
        use_images=args.images,
    )
    md = render_eval_markdown(report)
    print(md)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(report_to_json(report), encoding="utf-8")
    if args.backend == "ollama" and args.split in ("heldout", "all"):
        n = log_heldout_run(report)
        print(f"Held-out set has now been run {n} time(s). Report the FIRST run and say how many you did.")
    return 0


# ---------------------------------------------------------------- scan / redact
_TEXT_EXT = {".txt", ".md", ".log", ".json", ".yml", ".yaml", ".xml", ".csv", ".html", ".conf", ".ini", ".env", ".py", ".js"}


def _iter_files(paths: list[str]):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in _TEXT_EXT and f.stat().st_size < 2_000_000:
                    yield f
        elif p.is_file():
            yield p


def cmd_scan(args: argparse.Namespace) -> int:
    from .verify.secrets import scan_text

    total = 0
    for f in _iter_files(args.paths):
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for hit in scan_text(text, source=str(f)):
            line = text.count("\n", 0, hit.start) + 1
            total += 1
            print(f"{f}:{line}: {hit.kind} {hit.preview} ({hit.confidence})")
    print(f"\n{total} secret/PII value(s) found." + (" Redact before you send this report." if total else ""))
    return 1 if total else 0


def cmd_redact(args: argparse.Namespace) -> int:
    from .verify.secrets import redact

    text = Path(args.file).read_text(encoding="utf-8")
    red, hits = redact(text)
    if args.output:
        Path(args.output).write_text(red, encoding="utf-8")
        print(f"{len(hits)} value(s) masked -> {args.output}")
    else:
        sys.stdout.write(red)
    return 0


# ---------------------------------------------------------------- serve
def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .server import create_app

    app = create_app(llm=make_llm(args.backend, args.model))
    print(f"PenMunshi UI on http://{args.host}:{args.port}  (backend: {args.backend}). Local only: Ctrl+C to stop.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


# ---------------------------------------------------------------- import / retest
def cmd_import(args: argparse.Namespace) -> int:
    from .importers import import_tool_output

    try:
        created = import_tool_output(args.file, args.out, fmt=args.format)
    except Exception as exc:
        print(f"[FAIL] Import error: {exc}", file=sys.stderr)
        return 1

    print(f"Imported {len(created)} finding(s) from {args.file} into {args.out}/")
    for folder in created:
        print(f"  -> {folder.name}")
    return 0


def cmd_retest(args: argparse.Namespace) -> int:
    from .retest import retest_files

    try:
        res = retest_files(args.old_report, args.new_report)
    except Exception as exc:
        print(f"[FAIL] Retest comparison error: {exc}", file=sys.stderr)
        return 1

    if args.format == "markdown":
        output = res.render_markdown()
    else:
        output = res.render_table()

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Retest diff written to {args.out}")
    else:
        print(output)
    return 0


def cmd_export_demo(args: argparse.Namespace) -> int:
    from .export_demo import export_demo_site

    try:
        out = export_demo_site(out_dir=args.out, source_json=args.data)
        print(f"Static demo site built at {out}/ (index.html, demo-data.json, README.md)")
        return 0
    except Exception as exc:
        print(f"[FAIL] Export demo error: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="penmunshi", description="Offline-first pentest report copilot")
    p.add_argument("--version", action="version", version=f"penmunshi {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="check Ollama, the model and the GPU")
    d.add_argument("--model")
    d.set_defaults(fn=cmd_doctor)

    a = sub.add_parser("analyze", help="analyze an engagement folder and write the report")
    a.add_argument("engagement")
    a.add_argument("--out", default="out/report")
    a.add_argument("--backend", choices=["ollama", "fake"], default="ollama")
    a.add_argument("--model")
    a.add_argument("--formats", default="html,md,docx,json")
    a.set_defaults(fn=cmd_analyze)

    e = sub.add_parser("eval", help="run the evaluation harness")
    e.add_argument("--backend", choices=["fake", "ollama"], default="fake")
    e.add_argument("--model")
    e.add_argument("--split", choices=["all", "dev", "heldout"], default="all")
    e.add_argument("--cases")
    e.add_argument("--out")
    e.add_argument("--json")
    e.add_argument("--no-faults", action="store_true", help="fake backend without injected faults")
    e.add_argument("--images", action="store_true", help="send case images to the model if the case has files")
    e.set_defaults(fn=cmd_eval)

    s = sub.add_parser("scan", help="pre-flight: find secrets/PII in files before you send them")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("redact", help="mask secrets/PII in a text file")
    r.add_argument("file")
    r.add_argument("-o", "--output")
    r.set_defaults(fn=cmd_redact)

    v = sub.add_parser("serve", help="start the local web UI")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--backend", choices=["ollama", "fake"], default="ollama")
    v.add_argument("--model")
    v.set_defaults(fn=cmd_serve)

    imp = sub.add_parser("import", help="deterministic importer for Nmap XML and Burp XML issues")
    imp.add_argument("file", help="path to scanner output XML file")
    imp.add_argument("-o", "--out", default="findings", help="directory to write finding folders")
    imp.add_argument("--format", choices=["auto", "nmap", "burp"], default="auto", help="scanner format")
    imp.set_defaults(fn=cmd_import)

    ret = sub.add_parser("retest", help="compare old and new reports: resolved, open, regressed, new")
    ret.add_argument("old_report", help="path to original report.json")
    ret.add_argument("new_report", help="path to retest report.json")
    ret.add_argument("-o", "--out", help="optional output file path")
    ret.add_argument("--format", choices=["table", "markdown"], default="table", help="output format")
    ret.set_defaults(fn=cmd_retest)

    exp = sub.add_parser("export-demo", help="build static demonstration site with recorded replay data")
    exp.add_argument("-o", "--out", default="site", help="output directory for the demo site")
    exp.add_argument("--data", help="path to source report.json for replay")
    exp.set_defaults(fn=cmd_export_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
