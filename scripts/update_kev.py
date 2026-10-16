"""Download the CISA Known Exploited Vulnerabilities catalog to data/kev.json (needs internet).

Run once while online; PenMunshi then flags known-exploited CVEs fully offline.
    python scripts/update_kev.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT = Path("data/kev.json")


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    r = httpx.get(URL, timeout=60, follow_redirects=True)
    r.raise_for_status()
    data = r.json()
    OUT.write_text(json.dumps(data), encoding="utf-8")
    print(f"saved {len(data.get('vulnerabilities', []))} entries to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
