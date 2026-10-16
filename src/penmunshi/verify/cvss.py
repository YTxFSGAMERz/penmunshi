"""CVSS v3.1 maths, owned by code. The model proposes metric letters; software does the rest."""

from __future__ import annotations

import re

from cvss import CVSS3

ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALID = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "NLH",
    "I": "NLH",
    "A": "NLH",
}
_VECTOR_RE = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)
_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "low": "Low",
    "none": "None",
    "info": "None",
    "informational": "None",
}


def build_vector(metrics: dict) -> str | None:
    """Return 'CVSS:3.1/AV:N/...' or None if any metric is missing or invalid."""
    parts = []
    for key in ORDER:
        value = str(metrics.get(key, "")).upper()
        if value not in VALID[key] or len(value) != 1:
            return None
        parts.append(f"{key}:{value}")
    return "CVSS:3.1/" + "/".join(parts)


def find_vector(text: str | None) -> str | None:
    """Find a complete CVSS v3 vector typed by the tester (tester input beats the model)."""
    m = _VECTOR_RE.search(text or "")
    return m.group(0) if m else None


def severity_from_score(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_vector(vector: str | None) -> tuple[float, str] | None:
    """Base score and severity band computed by the `cvss` library."""
    if not vector:
        return None
    try:
        base = float(CVSS3(vector).scores()[0])
    except Exception:
        return None
    return base, severity_from_score(base)


def normalise_severity(text: str | None) -> str | None:
    if not text:
        return None
    return _ALIASES.get(text.strip().lower())


def metrics_from_vector(vector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        out[key] = value
    return out
