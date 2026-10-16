# Architecture

One rule: **the model reads and writes, code owns the facts.**

## Data flow (`src/penmunshi/pipeline.py`)

1. **Ingest**: notes, tool output, screenshots, optional tester overrides (`finding.yml` or a CVSS vector typed in the notes).
2. **Vision pass**: each screenshot is downscaled (`llm/images.py`) and transcribed by Gemma. The prompt forbids interpretation; unreadable text becomes `[unreadable]`.
3. **Secret scan and redaction** (`verify/secrets.py`): every source is scanned. Raw values are kept in memory only (`known_values`) so they can be masked again in the model's output. Nothing raw goes into a prompt.
4. **Draft pass**: Gemma returns a `FindingDraft` JSON object (schema-enforced by Ollama structured outputs, `llm/schema.py`). One retry with the validation error in the prompt.
5. **Verification** (all deterministic):
   - `verify/cvss.py`: metric letters to vector to score/severity. Tester vector beats the model.
   - `verify/ids.py`: CVE provenance, CWE catalog check, canonical names.
   - `verify/claims.py`: every claim's quote must exist in its cited source (exact or fuzzy >= 0.85, min 8 chars).
   - output masking: pattern + exact known values.
   - `verify/lint.py`: report-quality rules (repro steps, impact, remediation, evidence, severity mismatch...).
6. **Status**: `ready` only if no lint errors, all claims supported, confidence is confirmed/likely. Otherwise `needs_review`.
7. **Render** (`report/`): HTML (Jinja, autoescaped), Markdown, DOCX, each with a verification appendix.

## Modules

| Path | Responsibility |
|---|---|
| `llm/` | `LLM` protocol, `OllamaLLM`, `FakeLLM`, prompts, schema inlining, image prep |
| `verify/` | all deterministic checks. No model calls allowed here |
| `pipeline.py` | orchestration, engagement folder loading, executive summary |
| `report/` | renderers and report helpers (severity counts computed by code) |
| `eval/` | cases (`eval/cases/*.json`), harness, scripted fault-injecting fake model |
| `server.py`, `web/index.html` | local FastAPI app and the offline single-page UI |
| `cli.py` | `doctor`, `analyze`, `eval`, `scan`, `redact`, `serve` |

## Adding a secret detector

1. Add a `Detector(...)` to `DETECTORS` in `verify/secrets.py`. Order is priority; put specific patterns first.
2. Add a validator (checksum) if the format has one. Validators remove false positives.
3. Add tests in `tests/test_secrets.py`: one positive, one near-miss, one "never leaks in redact()".
4. If it is part of a case, add the raw value to the case's `seeded_secrets` and the kind to `gold.secrets`.

## Why local, why a protocol

`LLM` is a three-method protocol so tests, CI and the eval run without a model, and so a different local backend (llama.cpp server, LM Studio) is a 40-line class. No hosted API is a supported backend: the privacy argument is the product.
