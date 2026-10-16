# PenMunshi Static Demo

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
