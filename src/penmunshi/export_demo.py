"""Export static demo site for recorded replay and hosting."""

from __future__ import annotations

import shutil
from pathlib import Path


def export_demo_site(
    out_dir: Path | str = "site",
    source_json: Path | str | None = None,
) -> Path:
    """Build the static demonstration site with recorded replay data."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Copy web UI index.html
    web_index = Path(__file__).parent / "web" / "index.html"
    dest_index = out_path / "index.html"
    shutil.copyfile(web_index, dest_index)

    # 2. Prepare demo-data.json from a real run
    demo_file = out_path / "demo-data.json"
    if source_json and Path(source_json).is_file():
        shutil.copyfile(source_json, demo_file)
    else:
        # Fall back to available demo run outputs or generate from examples/acme-demo
        candidates = [
            Path("out/demo-polished/report.json"),
            Path("out/acme-real/report.json"),
            Path("out/demo/report.json"),
        ]
        found = next((p for p in candidates if p.is_file()), None)
        if found:
            shutil.copyfile(found, demo_file)
        else:
            from .llm import FakeLLM
            from .pipeline import analyze_engagement

            rep = analyze_engagement(Path("examples/acme-demo"), FakeLLM())
            demo_file.write_text(rep.model_dump_json(indent=2), encoding="utf-8")

    # 3. Write site README clarifying recorded replay
    readme_content = """# PenMunshi Static Demo

This directory contains the static demonstration page for **PenMunshi** (offline-first pentest report copilot).

## What you are seeing:
- **Recorded Offline Replay**: This page loads `demo-data.json` generated from an offline assessment run on `examples/acme-demo`.
- **Honesty Guarantee**: No LLM inference runs inside this hosted browser session. The top banner explicitly indicates that this is a recorded replay.
- **Interactive Features**: You can inspect masked secret bounding boxes on screenshots, click claims to jump to highlighted evidence transcripts, and review CVSS v3.1 calculations.

To run live Gemma 4 vision and drafting on your machine:
```bash
git clone https://github.com/your-repo/penmunshi.git
cd penmunshi
pip install -e .
penmunshi doctor
penmunshi serve --backend ollama
```
"""
    (out_path / "README.md").write_text(readme_content, encoding="utf-8")

    return out_path
