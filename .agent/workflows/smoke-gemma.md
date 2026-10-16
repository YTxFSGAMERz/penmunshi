---
description: First real run against local Gemma via Ollama, with timings
---

1. Run `penmunshi doctor`. If the model is missing run `ollama pull gemma4:e4b`, then doctor again.
2. Run `penmunshi analyze examples/acme-demo --out out/demo-real` and note per-finding `timings_ms` from `out/demo-real/report.json`.
3. Open `out/demo-real/report.html`. For each finding check: transcript matches the screenshot, claims quote real text, secrets are masked, severity is code-computed.
4. Write every miss you see into `docs/EVAL.md` under "Failure log" with the finding id and what the model did wrong. Fix prompts or verification, never hide a miss.
5. If a call takes longer than 60 s on this laptop, try `PENMUNSHI_MODEL=gemma4:e2b` and record both timings.
