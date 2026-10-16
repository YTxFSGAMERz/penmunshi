"""Report-quality lint. Rules mirror what buyers of VAPT reports complain about:
no repro steps, no evidence, no business impact, severity that contradicts the CVSS maths."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..models import EvidenceItem, LintIssue, VerifiedFinding
from .cvss import normalise_severity

GENERIC_TITLES = {
    "vulnerability",
    "security issue",
    "finding",
    "issue",
    "untitled",
    "untitled finding",
    "bug",
}
_PLACEHOLDER = re.compile(r"\b(lorem ipsum|todo|tbd|placeholder)\b|<insert", re.I)


def _short(text: str, minimum: int = 15) -> bool:
    return len(text.strip()) < minimum


def check_evidence_mismatches(notes: str, evidence: Sequence[EvidenceItem]) -> list[str]:
    """Check for numerical values, status codes, and hosts in notes that contradict or are missing in evidence."""
    if not notes or not evidence:
        return []

    transcripts = [e.transcript for e in evidence if e.transcript]
    if not transcripts:
        return []
    all_transcripts = "\n".join(transcripts)
    mismatches: list[str] = []

    # 1. HTTP status codes
    notes_codes = set(re.findall(r"\b(?:HTTP|status|code)\s*(?:code\s*)?([1-5]\d{2})\b", notes, re.I))
    notes_codes.update(
        re.findall(
            r"\b([1-5]\d{2})\s+(?:OK|Found|Redirect|Forbidden|Unauthorized|Internal Server Error|Bad Request|Not Found|Gateway)\b",
            notes,
            re.I,
        )
    )

    trans_codes = set(re.findall(r"\bHTTP/\d(?:\.\d)?\s+([1-5]\d{2})\b", all_transcripts, re.I))
    trans_codes.update(re.findall(r"\b(?:status|code)[:\s]+([1-5]\d{2})\b", all_transcripts, re.I))

    if notes_codes and trans_codes:
        for nc in sorted(notes_codes):
            if nc not in trans_codes and nc not in all_transcripts:
                mismatches.append(
                    f"HTTP status code '{nc}' in notes contradicts evidence transcripts ({', '.join(sorted(trans_codes))})"
                )

    # 2. Port numbers
    notes_ports = set(re.findall(r"\bport\s+(\d{2,5})\b", notes, re.I))
    notes_ports.update(re.findall(r":(\d{2,5})\b", notes))
    notes_ports = {p for p in notes_ports if not (len(p) == 4 and p.startswith("20"))}

    trans_ports = set(re.findall(r"\bport\s+(\d{2,5})\b", all_transcripts, re.I))
    trans_ports.update(re.findall(r":(\d{2,5})\b", all_transcripts))
    trans_ports = {p for p in trans_ports if not (len(p) == 4 and p.startswith("20"))}

    if notes_ports and trans_ports:
        for np in sorted(notes_ports):
            if np not in trans_ports and np not in all_transcripts:
                mismatches.append(
                    f"Port '{np}' in notes contradicts evidence transcripts ({', '.join(sorted(trans_ports))})"
                )

    # 3. Hostnames / domains
    notes_hosts = set(
        re.findall(
            r"\b(?:host|target|domain)[:\s]+([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\b", notes, re.I
        )
    )
    notes_hosts.update(re.findall(r"https?://([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", notes, re.I))

    trans_hosts = set(re.findall(r"\bHost:\s*([a-z0-9][a-z0-9.-]+)", all_transcripts, re.I))
    trans_hosts.update(re.findall(r"https?://([a-z0-9][a-z0-9.-]+)", all_transcripts, re.I))

    if notes_hosts and trans_hosts:
        for nh in sorted(notes_hosts):
            nh_lower = nh.lower()
            all_trans_lower = all_transcripts.lower()
            if (
                nh_lower not in [th.lower() for th in trans_hosts]
                and nh_lower not in all_trans_lower
            ):
                mismatches.append(
                    f"Host '{nh}' in notes contradicts evidence ({', '.join(sorted(trans_hosts))})"
                )

    return mismatches


def lint_finding(
    f: VerifiedFinding,
    *,
    notes: str = "",
    tester_severity: str | None = None,
    has_evidence: bool = True,
    output_redactions: int = 0,
    vision_errors: Sequence[str] = (),
    draft_error: str = "",
) -> list[LintIssue]:
    issues: list[LintIssue] = []

    def add(code: str, level: str, message: str) -> None:
        issues.append(LintIssue(code=code, level=level, message=message))  # type: ignore[arg-type]

    if draft_error:
        add("draft_failed", "error", f"The model did not return a usable draft: {draft_error}")
        return issues
    if not f.steps_to_reproduce:
        add("no_repro_steps", "error", "No reproduction steps. A client engineer cannot verify this.")
    if _short(f.impact):
        add("no_impact", "error", "Business impact is missing or too short.")
    if not f.remediation or all(_short(r, 10) for r in f.remediation):
        add("no_remediation", "error", "Remediation advice is missing or too short.")
    if not has_evidence:
        add("no_evidence", "warn", "No screenshots or tool output attached: notes only.")
    if f.title.strip().lower() in GENERIC_TITLES or len(f.title.strip()) < 8:
        add("generic_title", "warn", "Title is generic. Name the weakness and the affected asset.")
    blob = " ".join([f.title, f.summary, f.description, f.impact])
    if _PLACEHOLDER.search(blob):
        add("placeholder_text", "error", "Placeholder text found in the draft.")

    bad = [c for c in f.claims if not c.supported]
    if f.claims and bad:
        level = "error" if len(bad) * 2 > len(f.claims) else "warn"
        add(
            "unsupported_claims",
            level,
            f"{len(bad)} of {len(f.claims)} claims could not be matched to the evidence.",
        )
    if not f.claims:
        add("no_claims", "warn", "The draft quotes no evidence for any statement.")

    if f.removed_ids:
        listed = ", ".join(r.id for r in f.removed_ids)
        add("ids_removed", "info", f"Removed identifiers that failed verification: {listed}.")

    wanted = normalise_severity(tester_severity)
    if wanted and f.severity not in ("Unrated",) and wanted != f.severity:
        add(
            "severity_mismatch",
            "warn",
            f"Tester severity is {wanted} but the CVSS vector computes to {f.severity}.",
        )
    if f.severity == "Unrated":
        add("unrated", "error", "No valid CVSS vector, so no severity could be computed.")
    if f.confidence == "needs_more_evidence":
        add("provisional", "warn", "The model flagged missing evidence: treat severity as provisional.")

    unreadable = sum(e.unreadable_parts for e in f.evidence) + sum(
        e.transcript.count("[unreadable]") for e in f.evidence
    )
    if unreadable:
        add("unreadable_evidence", "warn", f"{unreadable} unreadable part(s) in screenshots: re-capture them.")
    for err in vision_errors:
        add("vision_failed", "warn", f"Screenshot could not be read: {err}")

    if f.secrets:
        add(
            "secrets_masked",
            "info",
            f"{len(f.secrets)} secret/PII value(s) masked. Re-check screenshots before sending.",
        )
    if output_redactions:
        add(
            "secret_in_output",
            "error",
            f"The model output contained {output_redactions} secret-like value(s): they were masked.",
        )
    if notes and f.evidence:
        for mismatch in check_evidence_mismatches(notes, f.evidence):
            add("evidence_mismatch", "warn", mismatch)
    return issues
