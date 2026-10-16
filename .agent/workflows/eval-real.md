---
description: Real-model evaluation on dev, then the held-out split exactly once
---

1. `penmunshi eval --backend ollama --split dev --out docs/EVAL_RESULTS_dev.md --json out/eval-dev.json`. Tune prompts and verification on dev only.
2. When dev is stable, run `penmunshi eval --backend ollama --split heldout --out docs/EVAL_RESULTS_heldout.md`. Do it once. The run is logged in `.penmunshi/heldout_runs.jsonl`; the write-up must state how many times it was run.
3. Paste both tables into `docs/EVAL.md` unedited. Add one paragraph per failure: what the model did, why the verifier did or did not catch it.
