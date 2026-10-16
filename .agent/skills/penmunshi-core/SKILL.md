---
name: penmunshi-core
description: Read FIRST for any task in the PenMunshi repo. Holds the mission, the non-negotiable invariants (the model proposes and code decides; secrets masked before and after the model; everything stays local), the module map and the commands. Use it before reading, editing, running or planning anything here, even for a one-line fix, because every other skill assumes it.
---

# PenMunshi core

## Mission
An offline-first pentest/VAPT report copilot. A local Gemma 4 model (through Ollama) drafts findings from raw notes and screenshots; deterministic code verifies every fact. It is an entry for DEV's Hacktoberfest Open-Source AI Challenge, Week 2 (Side Hustle). Judges weigh the write-up most, then relevance (open models at the core, someone would pay), creativity and technical execution.

## The rule, and why
**The model reads and writes; code owns the facts.** Small local models are fluent and sometimes confidently wrong ("wrong and calm"). Anything that code can check (scores, identifiers, quotes, secrets) must be checked by code, otherwise a report can lie in a professional tone.

## Invariants (break none)
1. Severity, score and vector come from `verify/cvss.py`. The model emits metric letters only. A vector typed by the tester always wins.
2. CVE ids survive only if written in the notes or evidence. CWE ids must exist in `data/cwe_catalog.json` (or be written by the tester).
3. Every claim quotes its evidence. Unsupported claims are flagged and force `needs_review`.
4. Secrets are masked before any prompt and again in model output (patterns plus exact values already seen). Raw values exist in memory only.
5. No hosted LLM, no CDN assets, no telemetry. Optional integrations are opt-in, off by default, and send metadata only.
6. The UI builds DOM with `h()`/`textContent`. Never `innerHTML` with finding data: evidence can contain HTML payloads.
7. No invented numbers, quotes, users or screenshots. Unknowns are written `TODO(human)`.
8. No real client data. Demo material is fictional (`*.acme.test`, AWS documentation example keys).

## Map
| Path | Role |
|---|---|
| `src/penmunshi/pipeline.py` | orchestration: vision, redaction, draft, verification, status |
| `src/penmunshi/verify/` | all deterministic checks (no model calls) |
| `src/penmunshi/llm/` | `LLM` protocol, Ollama client, fake model, prompts, schema |
| `src/penmunshi/report/` | HTML, Markdown, DOCX renderers |
| `src/penmunshi/eval/` | cases, harness, fault-injecting scripted model |
| `src/penmunshi/server.py`, `web/index.html` | local API and offline UI |
| `tests/`, `tests/ui/smoke.mjs` | model-free tests, jsdom UI smoke test |
| `docs/`, `HUMAN_TODO.md` | architecture, eval log, post outline, plans, tasks only the human can do |

## Commands
```
pip install -e ".[dev]"
ruff check . && python -m pytest -q
python -m penmunshi eval --backend fake          # verification layer, fault injection
python -m penmunshi doctor                       # Ollama, model, GPU
python -m penmunshi analyze examples/acme-demo --out out/demo
python -m penmunshi serve                        # UI on 127.0.0.1:8765
python -m penmunshi scan .                       # secret/PII pre-flight
```

## Definition of done for any change
- A model-free test covers it (use `FakeLLM`). `ruff check .` and `pytest` are green.
- If it changes behaviour a judge could see: README or docs updated, and a line added to `docs/EVAL.md` if it fixes a real failure.
- If it needs a real run or a person, it is written in `HUMAN_TODO.md`, not faked.

## Load next
`verification-layer` (checks), `ollama-gemma-local` (model), `eval-and-honesty` (numbers), `screenshot-redaction`, `report-quality`, `ui-polish-offline`, `dev-post-writer`, `first-user-validation`, `demo-video-90s`, `partner-categories`, `five-day-sprint`, `submission-qa`.
