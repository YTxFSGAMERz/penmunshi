"""Common utilities and data structures for deterministic tool importers."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ImportedFinding:
    slug: str
    title: str
    asset: str
    notes: str
    tool_output: str
    severity: str | None = None
    confidence: str | None = None


def slugify(text: str, max_len: int = 50) -> str:
    """Turn free text into a safe folder name."""
    s = text.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:max_len] or "finding"


def clean_html_text(raw: str) -> str:
    """Strip HTML tags and unescape entities into clean markdown/text."""
    if not raw:
        return ""
    # Convert <br>, <p>, <li> to newlines
    text = re.sub(r"<(?:br|/p|/li)>", "\n", raw, flags=re.IGNORECASE)
    # Strip remaining tags
    text = re.sub(r"<[^>]+>", "", text)
    # Unescape HTML entities (&lt;, &gt;, &amp;, etc.)
    text = html.unescape(text)
    # Normalize multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def write_imported_findings(findings: list[ImportedFinding], out_dir: Path) -> list[Path]:
    """Write imported findings into finding folders containing notes.md, tool_output.txt, finding.yml."""
    out_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    seen_slugs: dict[str, int] = {}

    for i, item in enumerate(findings, 1):
        base_slug = f"{i:02d}-{item.slug}" if item.slug else f"{i:02d}-finding"
        count = seen_slugs.get(base_slug, 0)
        seen_slugs[base_slug] = count + 1
        folder_name = base_slug if count == 0 else f"{base_slug}-{count}"

        folder = out_dir / folder_name
        folder.mkdir(parents=True, exist_ok=True)

        (folder / "notes.md").write_text(item.notes.strip() + "\n", encoding="utf-8")
        if item.tool_output.strip():
            (folder / "tool_output.txt").write_text(item.tool_output.strip() + "\n", encoding="utf-8")

        yml_lines = []
        if item.severity:
            yml_lines.append(f"severity: {item.severity.capitalize()}")
        if item.confidence:
            yml_lines.append(f"confidence: {item.confidence.lower()}")
        if yml_lines:
            (folder / "finding.yml").write_text("\n".join(yml_lines) + "\n", encoding="utf-8")

        created.append(folder)

    return created
