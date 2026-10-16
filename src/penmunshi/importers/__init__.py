"""Deterministic tool output importers (Nmap, Burp Suite)."""

from __future__ import annotations

from pathlib import Path

from .burp import import_burp, parse_burp_xml
from .common import ImportedFinding, write_imported_findings
from .nmap import import_nmap, parse_nmap_xml


def detect_format(file_path: Path | str) -> str:
    """Detect tool output format by examining header content."""
    path = Path(file_path)
    sample = path.read_text(encoding="utf-8", errors="replace")[:4096].lower()
    if "<nmaprun" in sample:
        return "nmap"
    if "<issues" in sample:
        return "burp"
    raise ValueError(f"Could not automatically detect scanner format for {path.name}. Specify --format nmap|burp.")


def import_tool_output(
    file_path: Path | str,
    out_dir: Path | str,
    fmt: str = "auto",
) -> list[Path]:
    """Import tool output file into finding folders."""
    path = Path(file_path)
    if fmt == "auto":
        fmt = detect_format(path)

    if fmt == "nmap":
        return import_nmap(path, out_dir)
    elif fmt == "burp":
        return import_burp(path, out_dir)
    else:
        raise ValueError(f"Unsupported importer format: {fmt}. Choose 'nmap' or 'burp'.")


__all__ = [
    "ImportedFinding",
    "detect_format",
    "import_burp",
    "import_nmap",
    "import_tool_output",
    "parse_burp_xml",
    "parse_nmap_xml",
    "write_imported_findings",
]
