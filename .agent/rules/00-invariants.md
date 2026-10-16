# PenMunshi invariants (always on)

- Model proposes, code decides. CVSS score/severity, CVE/CWE ids, quote checks and secret masking are computed by code in `src/penmunshi/verify/`. The model never writes a score or a severity.
- Secrets are masked BEFORE any text reaches a model prompt, and masked AGAIN in model output (pattern + exact known values).
- Everything stays local: no hosted LLM APIs, no CDN assets, no telemetry. Optional integrations must be opt-in, off by default, and send metadata only (never finding content).
- DOM is built with `textContent`/`h()` only. Evidence can contain HTML payloads; never use `innerHTML` with finding data.
- No fabricated metrics, quotes, users or screenshots. Numbers in docs come from real runs of `penmunshi eval`. Unknowns are written as `TODO(human)`.
- No real client data in the repo. Demo material is fictional (`*.acme.test`, AWS docs example keys).
- Every behaviour change needs a model-free test (use `FakeLLM`) and passes `ruff check .` and `pytest`.
