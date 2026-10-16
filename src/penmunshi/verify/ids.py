"""Identifier verification: the model may suggest CVE/CWE ids, code decides what survives.

CVE rule  : kept only if the id is written in the tester's notes or evidence (provenance).
CWE rule  : kept if it exists in the local catalog (name is replaced by the canonical one) or
            is written in the sources. Anything else is stripped and reported.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

from ..models import CveRef, CweRef, RemovedId
from .catalog import Catalog

_DASH = "\u2010-\u2015-"
CVE_RE = re.compile(rf"CVE[{_DASH} ]?(\d{{4}})[{_DASH} ]?(\d{{4,7}})", re.I)
CWE_RE = re.compile(rf"CWE[{_DASH} ]?(\d{{1,5}})", re.I)


def normalise_cve(raw: object) -> str | None:
    m = CVE_RE.search(str(raw))
    if not m:
        return None
    year = int(m.group(1))
    if year < 1999 or year > _dt.date.today().year + 1:
        return None
    return f"CVE-{year}-{m.group(2)}"


def normalise_cwe(raw: object) -> str | None:
    m = re.search(r"(\d{1,5})", str(raw))
    return str(int(m.group(1))) if m else None


def extract_cves(text: str) -> set[str]:
    return {n for m in CVE_RE.finditer(text or "") if (n := normalise_cve(m.group(0)))}


def extract_cwes(text: str) -> set[str]:
    return {str(int(m.group(1))) for m in CWE_RE.finditer(text or "")}


@dataclass
class IdResult:
    cve: list[CveRef] = field(default_factory=list)
    cwe: list[CweRef] = field(default_factory=list)
    removed: list[RemovedId] = field(default_factory=list)


def verify_ids(
    cve_ids: list[str], cwe_ids: list[str], sources: dict[str, str], catalog: Catalog
) -> IdResult:
    source_cves: set[str] = set()
    source_cwes: set[str] = set()
    for text in sources.values():
        source_cves |= extract_cves(text)
        source_cwes |= extract_cwes(text)

    result = IdResult()
    seen: set[str] = set()
    for raw in cve_ids:
        norm = normalise_cve(raw)
        if norm is None:
            result.removed.append(
                RemovedId(id=str(raw), kind="cve", reason="malformed or implausible CVE identifier")
            )
        elif norm in seen:
            continue
        elif norm in source_cves:
            seen.add(norm)
            result.cve.append(CveRef(id=norm, known_exploited=norm in catalog.kev))
        else:
            seen.add(norm)
            result.removed.append(
                RemovedId(
                    id=norm,
                    kind="cve",
                    reason="not written in the tester notes or evidence (possible hallucination)",
                )
            )

    seen_cwe: set[str] = set()
    for raw in cwe_ids:
        num = normalise_cwe(raw)
        if num is None:
            result.removed.append(RemovedId(id=str(raw), kind="cwe", reason="malformed CWE identifier"))
        elif num in seen_cwe:
            continue
        elif num in catalog.cwe:
            seen_cwe.add(num)
            result.cwe.append(CweRef(id=f"CWE-{num}", name=catalog.cwe[num], verified=True))
        elif num in source_cwes:
            seen_cwe.add(num)
            result.cwe.append(CweRef(id=f"CWE-{num}", name="(not in local catalog)", verified=False))
        else:
            seen_cwe.add(num)
            result.removed.append(
                RemovedId(
                    id=f"CWE-{num}",
                    kind="cwe",
                    reason="not in the local CWE catalog and not written in the notes",
                )
            )
    return result
