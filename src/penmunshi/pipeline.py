"""The pipeline. One rule runs through it: the model reads and writes, code owns the facts.

  screenshots --(vision pass)--> transcripts
  notes + tool output + transcripts --(secret scan + redaction)--> safe text
  safe text --(draft pass)--> FindingDraft
  FindingDraft --(CVSS maths, id provenance, quote check, output redaction, lint)--> VerifiedFinding
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from . import __version__
from .config import Settings
from .llm.base import LLM, LLMError
from .llm.images import prepare_image
from .llm.prompts import (
    DRAFT_SCHEMA,
    DRAFT_SYSTEM,
    SUMMARY_SCHEMA,
    SUMMARY_SYSTEM,
    TRANSCRIBE_SCHEMA,
    TRANSCRIBE_SYSTEM,
    TRANSCRIBE_USER,
    build_draft_prompt,
)
from .models import (
    ClaimResult,
    Engagement,
    EvidenceItem,
    FindingDraft,
    LintIssue,
    Report,
    SecretPublic,
    VerifiedFinding,
)
from .report.common import count_severities
from .verify import claims as claims_mod
from .verify import cvss as cvss_mod
from .verify import ids as ids_mod
from .verify import lint as lint_mod
from .verify import secrets as secrets_mod
from .verify.catalog import Catalog
from .verify.redact_image import RedactionResult, redact_screenshot

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp"}
MIN_KNOWN_VALUE_LEN = 6  # shorter values would mangle ordinary words if masked by exact match


@dataclass
class EvidenceFile:
    name: str
    data: bytes


@dataclass
class FindingInput:
    id: str
    notes: str = ""
    tool_output: str = ""
    images: list[EvidenceFile] = field(default_factory=list)
    pre_transcribed: dict[str, str] = field(default_factory=dict)  # name -> text (skips vision)
    tester_vector: str | None = None
    tester_severity: str | None = None


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _draft_with_retry(llm: LLM, prompt: str, retries: int = 1) -> tuple[FindingDraft | None, str]:
    error = ""
    for _ in range(retries + 1):
        user = prompt
        if error:
            user += f"\n\nYour previous reply was rejected: {error}\nReturn corrected JSON only."
        try:
            raw = llm.generate_json(system=DRAFT_SYSTEM, user=user, schema=DRAFT_SCHEMA)
            return FindingDraft.from_llm(raw), ""
        except (LLMError, ValidationError, TypeError, ValueError, AttributeError) as exc:
            error = str(exc).replace("\n", " ")[:300]
    return None, error


def analyze_finding(
    inp: FindingInput,
    llm: LLM,
    *,
    catalog: Catalog | None = None,
    settings: Settings | None = None,
) -> VerifiedFinding:
    settings = settings or Settings.from_env()
    catalog = catalog or Catalog.load()
    t_total = time.perf_counter()
    timings: dict[str, int] = {}

    # 1. raw sources. They are never sent to the model unredacted.
    raw: dict[str, str] = {}
    if inp.notes.strip():
        raw["notes"] = inp.notes
    if inp.tool_output.strip():
        raw["tool_output"] = inp.tool_output

    # 2. vision pass (screenshots -> text)
    t0 = time.perf_counter()
    unreadable: dict[str, int] = {}
    vision_errors: list[str] = []
    image_names = {img.name for img in inp.images}
    for img in inp.images:
        try:
            data = prepare_image(img.data, settings.max_image_side)
            out = llm.generate_json(
                system=TRANSCRIBE_SYSTEM,
                user=TRANSCRIBE_USER,
                schema=TRANSCRIBE_SCHEMA,
                images=[data],
            )
            text_out = str(out.get("transcript", ""))
            text_out = text_out.replace("Transcribe this screenshot exactly.", "").strip()
            raw[img.name] = text_out
            unreadable[img.name] = int(out.get("unreadable_parts", 0) or 0)
        except (LLMError, ValueError, TypeError) as exc:
            raw[img.name] = ""
            vision_errors.append(f"{img.name}: {exc}")
    for name, text in inp.pre_transcribed.items():
        raw[name] = text
    timings["vision"] = _ms(t0)

    # 3. secret scan + redaction BEFORE anything reaches the draft prompt
    safe: dict[str, str] = {}
    hits_by_source: dict[str, int] = {}
    secrets: list[SecretPublic] = []
    known_values: dict[str, str] = {}  # raw value -> kind. Lives in memory only, never stored.
    for ref, text in raw.items():
        hits = secrets_mod.scan_text(text, source=ref)
        redacted = secrets_mod.redact_text(text, hits)
        safe[ref] = redacted
        hits_by_source[ref] = len(hits)
        for h in hits:
            value = text[h.start : h.end]
            if len(value) >= MIN_KNOWN_VALUE_LEN:
                known_values[value] = h.kind
        secrets += [
            SecretPublic(
                kind=h.kind,
                preview=h.preview,
                confidence=h.confidence,
                checksum_ok=h.checksum_ok,
                source=ref,
            )
            for h in hits
        ]

    # 3.5 screenshot redaction: opaque black bars over secret boxes, verified via re-OCR
    redacted_images: dict[str, RedactionResult] = {}
    known_val_list = list(known_values.keys())
    for img in inp.images:
        res = redact_screenshot(img.data, known_values=known_val_list)
        redacted_images[img.name] = res

    evidence = [
        EvidenceItem(
            name=ref,
            kind="screenshot" if ref in image_names else "text",
            transcript=text,
            secrets=hits_by_source.get(ref, 0)
            + (redacted_images[ref].masked_count if ref in redacted_images else 0),
            unreadable_parts=unreadable.get(ref, 0),
            redacted_image_data_uri=(
                redacted_images[ref].data_uri if ref in redacted_images else None
            ),
            boxes=(
                [b.to_dict() for b in redacted_images[ref].boxes]
                if ref in redacted_images
                else []
            ),
        )
        for ref, text in safe.items()
        if ref != "notes"
    ]
    has_evidence = any(ref != "notes" and text.strip() for ref, text in safe.items())

    # 4. draft pass
    t0 = time.perf_counter()
    draft, draft_error = _draft_with_retry(
        llm, build_draft_prompt(inp.id, safe), retries=settings.retries
    )
    timings["draft"] = _ms(t0)

    if draft is None:
        finding = VerifiedFinding(
            id=inp.id,
            title=f"Draft failed for {inp.id}",
            secrets=secrets,
            evidence=evidence,
            timings_ms={**timings, "total": _ms(t_total)},
        )
        finding.lint = lint_mod.lint_finding(
            finding, draft_error=draft_error, vision_errors=vision_errors
        )
        return finding

    # 5. deterministic verification
    t0 = time.perf_counter()
    tester_vec = cvss_mod.find_vector(inp.tester_vector) or cvss_mod.find_vector(inp.notes)
    if tester_vec:
        vector, source = tester_vec, "tester"
    else:
        vector = cvss_mod.build_vector(draft.cvss.model_dump())
        source = "model_metrics" if vector else "none"
    scored = cvss_mod.score_vector(vector)
    score, severity = scored if scored else (None, "Unrated")

    idr = ids_mod.verify_ids(draft.cve_ids, draft.cwe_ids, safe, catalog)
    claim_results = claims_mod.check_claims(draft.claims, safe)

    output_redactions = 0

    def clean(text: str) -> str:
        """Mask secrets in model output: by pattern, then by exact value seen in the input.

        The exact-value pass matters: a model can repeat a bare password that no regex would
        recognise ("Observed value: hunter2"), but we already know that value from the input.
        """
        nonlocal output_redactions
        red, hits = secrets_mod.redact(text, source="model_output")
        output_redactions += len(hits)
        for value in sorted(known_values, key=len, reverse=True):
            if value in red:
                output_redactions += red.count(value)
                red = red.replace(value, f"[REDACTED:{known_values[value]}]")
        return red

    cleaned_claims: list[ClaimResult] = []
    for c in claim_results:
        clean_text = clean(c.text)
        clean_quote = clean(c.quote)
        qs, qe = c.quote_start, c.quote_end
        if clean_quote != c.quote and c.found_in and c.found_in in safe:
            qs, qe = claims_mod.find_quote_offsets(clean_quote, safe[c.found_in])
        cleaned_claims.append(
            ClaimResult(
                text=clean_text,
                evidence_ref=c.evidence_ref,
                quote=clean_quote,
                supported=c.supported,
                score=c.score,
                found_in=c.found_in,
                quote_start=qs,
                quote_end=qe,
            )
        )
    claim_results = cleaned_claims
    finding = VerifiedFinding(
        id=inp.id,
        title=clean(draft.title),
        affected_asset=clean(draft.affected_asset),
        summary=clean(draft.summary),
        description=clean(draft.description),
        steps_to_reproduce=[clean(s) for s in draft.steps_to_reproduce],
        impact=clean(draft.impact),
        remediation=[clean(s) for s in draft.remediation],
        severity=severity,  # type: ignore[arg-type]
        severity_source=source,  # type: ignore[arg-type]
        cvss_vector=vector,
        cvss_score=score,
        cvss_rationale=clean(draft.cvss_rationale),
        confidence=draft.confidence,
        cwe=idr.cwe,
        cve=idr.cve,
        removed_ids=idr.removed,
        claims=claim_results,
        secrets=secrets,
        evidence=evidence,
    )
    finding.lint = lint_mod.lint_finding(
        finding,
        notes=inp.notes,
        tester_severity=inp.tester_severity,
        has_evidence=has_evidence,
        output_redactions=output_redactions,
        vision_errors=vision_errors,
    )
    has_error = any(i.level == "error" for i in finding.lint)
    unsupported = any(not c.supported for c in finding.claims)
    ok_confidence = finding.confidence in ("confirmed", "likely")
    finding.status = "ready" if not has_error and not unsupported and ok_confidence else "needs_review"
    timings["verify"] = _ms(t0)
    timings["total"] = _ms(t_total)
    finding.timings_ms = timings
    return finding


def summarize(findings: list[VerifiedFinding], llm: LLM) -> tuple[str, list[LintIssue]]:
    """Executive summary. Numbers are banned in the prose: code inserts the severity table."""
    items = [{"title": f.title, "severity": f.severity, "summary": f.summary} for f in findings]
    try:
        out = llm.generate_json(
            system=SUMMARY_SYSTEM,
            user=json.dumps(items, ensure_ascii=False),
            schema=SUMMARY_SCHEMA,
        )
    except LLMError as exc:
        return "", [LintIssue(code="summary_failed", level="warn", message=str(exc))]
    text = str(out.get("summary", "")).strip()
    issues: list[LintIssue] = []
    if any(ch.isdigit() for ch in text):
        issues.append(
            LintIssue(
                code="summary_has_numbers",
                level="warn",
                message="The summary states numbers. Check them against the severity table.",
            )
        )
    return text, issues


# ---------------------------------------------------------------- engagement folders
def load_finding_dir(path: Path) -> FindingInput:
    notes_file = next((p for p in (path / "notes.md", path / "notes.txt") if p.is_file()), None)
    notes = notes_file.read_text(encoding="utf-8") if notes_file else ""
    tool = path / "tool_output.txt"
    tool_output = tool.read_text(encoding="utf-8") if tool.is_file() else ""
    images: list[EvidenceFile] = []
    evidence_dir = path / "evidence"
    if evidence_dir.is_dir():
        for p in sorted(evidence_dir.iterdir()):
            if p.suffix.lower() in IMAGE_EXTS:
                images.append(EvidenceFile(name=p.name, data=p.read_bytes()))
    meta: dict = {}
    meta_file = path / "finding.yml"
    if meta_file.is_file():
        meta = yaml.safe_load(meta_file.read_text(encoding="utf-8")) or {}
    return FindingInput(
        id=path.name,
        notes=notes,
        tool_output=tool_output,
        images=images,
        tester_vector=meta.get("cvss"),
        tester_severity=meta.get("severity"),
    )


def load_engagement(path: Path) -> tuple[Engagement, list[FindingInput]]:
    meta_file = path / "engagement.yml"
    meta = yaml.safe_load(meta_file.read_text(encoding="utf-8")) if meta_file.is_file() else {}
    engagement = Engagement(**(meta or {}))
    root = path / "findings"
    dirs = sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
    return engagement, [load_finding_dir(d) for d in dirs]


def analyze_engagement(
    path: Path,
    llm: LLM,
    *,
    settings: Settings | None = None,
    catalog: Catalog | None = None,
    progress: Callable[[str], None] | None = None,
) -> Report:
    settings = settings or Settings.from_env()
    catalog = catalog or Catalog.load()
    engagement, inputs = load_engagement(path)
    findings: list[VerifiedFinding] = []
    for i, inp in enumerate(inputs, 1):
        if progress:
            progress(f"[{i}/{len(inputs)}] {inp.id}")
        findings.append(analyze_finding(inp, llm, catalog=catalog, settings=settings))
    return build_report(engagement, findings, llm)


def build_report(engagement: Engagement, findings: list[VerifiedFinding], llm: LLM) -> Report:
    summary, _issues = summarize(findings, llm) if findings else ("", [])
    return Report(
        engagement=engagement,
        findings=findings,
        executive_summary=summary,
        severity_counts=count_severities(findings),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool={"name": "PenMunshi", "version": __version__, "model": getattr(llm, "name", "unknown")},
    )
