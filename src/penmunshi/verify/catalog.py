"""Local reference data: a curated CWE subset and (optionally) the CISA KEV list."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class Catalog:
    cwe: dict[str, str]
    kev: frozenset[str]
    kev_source: str = "bundled sample"

    @classmethod
    def load(cls) -> Catalog:
        root = resources.files("penmunshi") / "data"
        cwe = json.loads((root / "cwe_catalog.json").read_text(encoding="utf-8"))
        kev, source = _load_kev(root)
        return cls(cwe=cwe, kev=frozenset(kev), kev_source=source)


def _parse_kev(raw: object) -> set[str]:
    if isinstance(raw, dict) and "vulnerabilities" in raw:
        return {str(v.get("cveID", "")).upper() for v in raw["vulnerabilities"] if v.get("cveID")}
    if isinstance(raw, list):
        return {str(x).upper() for x in raw}
    return set()


def _load_kev(root) -> tuple[set[str], str]:
    candidates = [os.environ.get("PENMUNSHI_KEV_PATH", ""), "data/kev.json"]
    for cand in candidates:
        if cand and Path(cand).is_file():
            try:
                ids = _parse_kev(json.loads(Path(cand).read_text(encoding="utf-8")))
                if ids:
                    return ids, cand
            except (OSError, ValueError):
                pass
    sample = json.loads((root / "kev_sample.json").read_text(encoding="utf-8"))
    return _parse_kev(sample), "bundled sample (run scripts/update_kev.py for the full list)"
