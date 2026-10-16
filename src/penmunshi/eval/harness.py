"""Evaluation harness.

Two modes:
  fake   - a scripted stand-in drafts each case from its gold labels and INJECTS faults
           (hallucinated CVE/CWE, wrong severity, fabricated quote, leaked secret). The numbers
           show whether the verification layer catches them. It says nothing about Gemma.
  ollama - the real model on the same cases. Numbers here are the ones for your write-up.

Discipline: tune on the `dev` split, run `heldout` once, report that first run honestly.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from ..config import Settings
from ..llm.base import LLM
from ..llm.fake import FakeLLM
from ..llm.ollama import OllamaLLM
from ..models import VerifiedFinding
from ..pipeline import EvidenceFile, FindingInput, analyze_finding
from ..verify import cvss as cvss_mod
from ..verify import ids as ids_mod
from ..verify.catalog import Catalog


@dataclass
class EvidenceSpec:
    name: str
    text: str = ""
    file: str = ""


@dataclass
class Case:
    id: str
    split: str
    title: str
    asset: str
    notes: str
    tool_output: str
    evidence: list[EvidenceSpec]
    gold: dict
    seeded_secrets: list[str] = field(default_factory=list)
    faults: dict = field(default_factory=dict)
    base_dir: Path | None = None


@dataclass
class CaseResult:
    id: str
    split: str
    severity_ok: bool
    vector_ok: bool
    cwe_ok: bool
    secret_recall: float
    leaks: int
    cve_emitted_unsourced: int
    faults_injected: int
    faults_caught: int
    claims_total: int
    claims_supported: int
    lint_errors: int
    status: str
    latency_ms: int
    severity: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    backend: str
    model: str
    split: str
    started: str
    results: list[CaseResult]


# ---------------------------------------------------------------- loading
def load_cases(directory: Path | None = None) -> list[Case]:
    if directory is None:
        res_dir = resources.files("penmunshi").joinpath("eval/cases")
        files = sorted(p for p in res_dir.iterdir() if p.name.endswith(".json"))
        texts = [(p.name, p.read_text(encoding="utf-8")) for p in files]
        base = Path(str(res_dir))
    else:
        paths = sorted(directory.glob("*.json"))
        texts = [(p.name, p.read_text(encoding="utf-8")) for p in paths]
        base = directory
    cases: list[Case] = []
    for _, text in texts:
        raw = json.loads(text)
        cases.append(
            Case(
                id=raw["id"],
                split=raw.get("split", "dev"),
                title=raw["title"],
                asset=raw.get("asset", ""),
                notes=raw["notes"],
                tool_output=raw.get("tool_output", ""),
                evidence=[EvidenceSpec(**e) for e in raw.get("evidence", [])],
                gold=raw["gold"],
                seeded_secrets=raw.get("seeded_secrets", []),
                faults=raw.get("faults", {}),
                base_dir=base,
            )
        )
    return cases


# ---------------------------------------------------------------- fake backend
class CaseScriptedLLM:
    """Drafts a case from its gold labels, then injects the faults listed in the case."""

    name = "fake:scripted"

    def __init__(self, case: Case, inject_faults: bool = True) -> None:
        self.case = case
        self.inject = inject_faults
        self._image_i = 0

    def generate_json(self, *, system: str, user: str, schema: dict, images: Sequence[bytes] = (),
                      temperature: float = 0.0) -> dict:
        props = schema.get("properties", {})
        if "transcript" in props:
            specs = [e for e in self.case.evidence if e.file]
            text = specs[self._image_i % len(specs)].text if specs else ""
            self._image_i += 1
            return {"transcript": text, "unreadable_parts": 0}
        if "title" in props:
            return self._draft(user)
        return {"summary": "The assessment found weaknesses that should be fixed before release."}

    def health(self) -> dict:
        return {"reachable": True, "backend": "fake", "model": self.name, "model_present": True}

    def _draft(self, user: str) -> dict:
        c, f = self.case, (self.case.faults if self.inject else {})
        # the scripted model only ever sees the REDACTED prompt, like a real model would
        seen_notes = _prompt_notes(user)  # redacted text: all a real model would see
        first = next((ln.strip() for ln in seen_notes.splitlines() if ln.strip()), c.title)
        quote = first[:160]
        redacted_first_two = " ".join(ln.strip() for ln in seen_notes.splitlines() if ln.strip())[:300]
        description = redacted_first_two or c.title
        if f.get("leak_secret") and c.seeded_secrets:
            description += f" Observed value: {c.seeded_secrets[0]}"
        claims = [{"text": c.title, "evidence_ref": "notes", "quote": quote}]
        if f.get("fake_claim"):
            claims.append(
                {
                    "text": "The server also disclosed its full admin password list.",
                    "evidence_ref": "notes",
                    "quote": "the server dumped the complete admin password list on request",
                }
            )
        draft = {
            "title": c.title,
            "affected_asset": c.asset,
            "summary": f"{c.title} on {c.asset}.",
            "description": description,
            "steps_to_reproduce": [f"Open {c.asset}.", "Repeat the request described in the notes."],
            "impact": "An attacker can abuse this weakness against real users and their data.",
            "remediation": [
                "Apply the standard fix for this weakness class.",
                "Add a regression test that fails when the fix is removed.",
            ],
            "cvss": cvss_mod.metrics_from_vector(c.gold["vector"]),
            "cvss_rationale": "Metrics follow the evidence in the notes.",
            "cwe_ids": list(c.gold.get("cwe", [])) + ([f["cwe"]] if f.get("cwe") else []),
            "cve_ids": list(c.gold.get("cves", [])) + ([f["cve"]] if f.get("cve") else []),
            "claims": claims,
            "confidence": "confirmed",
        }
        if f.get("severity_text"):
            draft["severity"] = f["severity_text"]  # rogue key: code must ignore it
        return draft


def _prompt_notes(user_prompt: str) -> str:
    import re

    m = re.search(r"TESTER NOTES:\n<<<\n(.*?)\n>>>", user_prompt, re.S)
    return m.group(1) if m else ""


class RecordingLLM:
    """Wraps any backend and records every prompt so the harness can check for leaks."""

    def __init__(self, inner: LLM) -> None:
        self.inner = inner
        self.name = getattr(inner, "name", "unknown")
        self.prompts: list[str] = []

    def generate_json(self, **kwargs) -> dict:  # type: ignore[no-untyped-def]
        self.prompts.append(kwargs.get("system", "") + "\n" + kwargs.get("user", ""))
        return self.inner.generate_json(**kwargs)

    def health(self) -> dict:
        return self.inner.health()


# ---------------------------------------------------------------- running
def _finding_input(case: Case, use_images: bool) -> FindingInput:
    inp = FindingInput(id=case.id, notes=case.notes, tool_output=case.tool_output)
    for e in case.evidence:
        if use_images and e.file and case.base_dir is not None:
            inp.images.append(EvidenceFile(name=e.name, data=(case.base_dir / e.file).read_bytes()))
        else:
            inp.pre_transcribed[e.name] = e.text
    return inp


def _source_text(case: Case) -> str:
    return "\n".join([case.notes, case.tool_output, *(e.text for e in case.evidence)])


def run_case(case: Case, llm: RecordingLLM, catalog: Catalog, settings: Settings,
             use_images: bool = False) -> CaseResult:
    t0 = time.perf_counter()
    finding: VerifiedFinding = analyze_finding(
        _finding_input(case, use_images), llm, catalog=catalog, settings=settings
    )
    latency = int((time.perf_counter() - t0) * 1000)
    blob = finding.model_dump_json()
    faults = case.faults if getattr(llm.inner, "inject", False) else {}

    gold = case.gold
    detected_kinds = {s.kind for s in finding.secrets}
    wanted = set(gold.get("secrets", []))
    recall = 1.0 if not wanted else len(wanted & detected_kinds) / len(wanted)

    leaks = sum(
        1
        for secret in case.seeded_secrets
        if secret in blob or any(secret in p for p in llm.prompts)
    )
    source_cves = ids_mod.extract_cves(_source_text(case))
    unsourced = sum(1 for c in finding.cve if c.id not in source_cves)

    injected = caught = 0
    notes: list[str] = []
    removed = {r.id.upper() for r in finding.removed_ids}
    if faults.get("cve"):
        injected += 1
        ok = faults["cve"].upper() in removed
        caught += ok
        notes.append(f"fake CVE {'caught' if ok else 'MISSED'}")
    if faults.get("cwe"):
        injected += 1
        ok = f"CWE-{faults['cwe']}" in removed
        caught += ok
        notes.append(f"fake CWE {'caught' if ok else 'MISSED'}")
    if faults.get("fake_claim"):
        injected += 1
        fake = [c for c in finding.claims if "admin password list" in c.text]
        ok = bool(fake) and not fake[0].supported
        caught += ok
        notes.append(f"fake claim {'caught' if ok else 'MISSED'}")
    if faults.get("severity_text"):
        injected += 1
        ok = finding.severity == gold["severity"]
        caught += ok
        notes.append(f"rogue severity {'ignored' if ok else 'USED'}")
    if faults.get("leak_secret"):
        injected += 1
        leaked = any(s in blob for s in case.seeded_secrets)
        ok = (not leaked) and any(i.code == "secret_in_output" for i in finding.lint)
        caught += ok
        notes.append(f"leaked secret {'masked+flagged' if ok else 'NOT CAUGHT'}")

    real_claims = [
        c for c in finding.claims if "admin password list" not in c.text
    ]
    return CaseResult(
        id=case.id,
        split=case.split,
        severity_ok=finding.severity == gold["severity"],
        vector_ok=finding.cvss_vector == gold["vector"],
        cwe_ok=any(c.id.replace("CWE-", "") in gold.get("cwe", []) for c in finding.cwe),
        secret_recall=round(recall, 3),
        leaks=leaks,
        cve_emitted_unsourced=unsourced,
        faults_injected=injected,
        faults_caught=caught,
        claims_total=len(real_claims),
        claims_supported=sum(c.supported for c in real_claims),
        lint_errors=sum(1 for i in finding.lint if i.level == "error"),
        status=finding.status,
        latency_ms=latency,
        severity=finding.severity,
        notes=notes,
    )


def run_eval(
    cases: list[Case],
    *,
    backend: str = "fake",
    model: str | None = None,
    split: str = "all",
    inject_faults: bool = True,
    use_images: bool = False,
    settings: Settings | None = None,
) -> EvalReport:
    settings = settings or Settings.from_env()
    catalog = Catalog.load()
    selected = [c for c in cases if split == "all" or c.split == split]
    results: list[CaseResult] = []
    used_model = "fake:scripted"
    for case in selected:
        if backend == "fake":
            llm = RecordingLLM(CaseScriptedLLM(case, inject_faults=inject_faults))
        elif backend == "ollama":
            real = OllamaLLM(settings, model=model)
            used_model = real.model
            llm = RecordingLLM(real)
        elif backend == "fake-default":
            llm = RecordingLLM(FakeLLM())
        else:
            raise ValueError(f"unknown backend: {backend}")
        results.append(run_case(case, llm, catalog, settings, use_images=use_images))
    return EvalReport(
        backend=backend,
        model=used_model,
        split=split,
        started=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        results=results,
    )


# ---------------------------------------------------------------- reporting
def _pct(n: int, d: int) -> str:
    return "n/a" if d == 0 else f"{100 * n / d:.0f}% ({n}/{d})"


def _summary_rows(rs: list[CaseResult]) -> dict[str, str]:
    lat = sorted(r.latency_ms for r in rs)
    p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else 0
    injected = sum(r.faults_injected for r in rs)
    return {
        "Cases": str(len(rs)),
        "Severity matches gold (code-computed)": _pct(sum(r.severity_ok for r in rs), len(rs)),
        "Exact CVSS vector matches gold": _pct(sum(r.vector_ok for r in rs), len(rs)),
        "Right CWE found": _pct(sum(r.cwe_ok for r in rs), len(rs)),
        "Seeded secret kinds detected": f"{100 * statistics.mean(r.secret_recall for r in rs):.0f}%" if rs else "n/a",
        "Seeded secrets leaked into prompts/outputs": str(sum(r.leaks for r in rs)),
        "CVE ids emitted without source in the notes": str(sum(r.cve_emitted_unsourced for r in rs)),
        "Real claims supported by their quote": _pct(sum(r.claims_supported for r in rs), sum(r.claims_total for r in rs)),
        "Injected faults caught": "n/a (no faults injected)" if injected == 0 else _pct(sum(r.faults_caught for r in rs), injected),
        ("Faulted cases sent to human review (expected: all)" if injected else "Cases ready without human fixes"): (
            _pct(sum(r.status == "needs_review" for r in rs if r.faults_injected), sum(1 for r in rs if r.faults_injected))
            if injected
            else _pct(sum(r.status == "ready" for r in rs), len(rs))
        ),
        "Latency per finding p50 / p95 (ms)": f"{int(statistics.median(lat)) if lat else 0} / {p95}",
    }


def render_eval_markdown(report: EvalReport) -> str:
    out = [
        "# PenMunshi eval results",
        "",
        f"- Backend: `{report.backend}`; model: `{report.model}`; split: `{report.split}`; run: {report.started}",
    ]
    if report.backend.startswith("fake"):
        out += [
            "- **Fake backend:** a scripted stand-in drafts each case and injects faults. These numbers "
            "test the verification layer only. They say nothing about Gemma.",
        ]
    out.append("")
    splits = ["dev", "heldout"] if report.split == "all" else [report.split]
    rows_by_split = {s: _summary_rows([r for r in report.results if r.split == s]) for s in splits}
    labels = list(next(iter(rows_by_split.values())).keys())
    out.append("| Metric | " + " | ".join(f"{s}" for s in splits) + " |")
    out.append("|---|" + "---|" * len(splits))
    for label in labels:
        out.append(f"| {label} | " + " | ".join(rows_by_split[s][label] for s in splits) + " |")
    out += ["", "## Per case", "", "| Case | Split | Severity | Gold ok | CWE ok | Faults caught | Status | ms |", "|---|---|---|---|---|---|---|---|"]
    for r in report.results:
        out.append(
            f"| {r.id} | {r.split} | {r.severity} | {'yes' if r.severity_ok else 'NO'} | "
            f"{'yes' if r.cwe_ok else 'NO'} | {r.faults_caught}/{r.faults_injected} | {r.status} | {r.latency_ms} |"
        )
    misses = [r for r in report.results if not (r.severity_ok and r.cwe_ok) or r.leaks]
    if misses:
        out += ["", "## Failures to explain in the write-up", ""]
        out += [f"- `{r.id}`: severity {r.severity} (gold {'ok' if r.severity_ok else 'differs'}), "
                f"CWE {'ok' if r.cwe_ok else 'missing'}, leaks {r.leaks}" for r in misses]
    return "\n".join(out) + "\n"


def report_to_json(report: EvalReport) -> str:
    return json.dumps(
        {**{k: v for k, v in asdict(report).items() if k != "results"},
         "results": [asdict(r) for r in report.results]},
        indent=2,
    )


def log_heldout_run(report: EvalReport, directory: Path = Path(".penmunshi")) -> int:
    """Append a line per held-out run so the write-up can say how many times it was looked at."""
    directory.mkdir(exist_ok=True)
    path = directory / "heldout_runs.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"when": report.started, "backend": report.backend, "model": report.model}) + "\n")
    return len(path.read_text(encoding="utf-8").splitlines())
