from __future__ import annotations

from ..models import VerifiedFinding

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unrated"]
SEVERITY_LABEL = {"None": "Informational"}


def label(severity: str) -> str:
    return SEVERITY_LABEL.get(severity, severity)


def count_severities(findings: list[VerifiedFinding]) -> dict[str, int]:
    """Counts are computed by code and inserted by the template - never written by the model."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {k: v for k, v in counts.items() if v or k in ("Critical", "High", "Medium", "Low")}


def sort_findings(findings: list[VerifiedFinding]) -> list[VerifiedFinding]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (rank.get(f.severity, 99), -(f.cvss_score or 0), f.id))
