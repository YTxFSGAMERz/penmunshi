---
name: eval-and-honesty
description: Build, run and report evaluations of PenMunshi without fooling yourself: adding eval cases (including real rendered screenshots), dev versus held-out discipline, fake versus real backend, metrics, failure logging, and how to turn results into honest tables for the README and the DEV post. Use whenever you add or edit eval cases, run penmunshi eval, write numbers anywhere, or analyse a model failure.
---

# Evaluation and honesty

Read `docs/EVAL.md` first. The winning Gemma write-up of the Weekend challenge was built on a held-out test, real documents next to synthetic ones, three model sizes side by side, and a failure it engineered out. This project's edge is the same discipline.

## Two backends, two meanings
- `--backend fake`: a scripted model drafts each case and **injects faults**. It tests the verification layer, runs in CI, and says nothing about Gemma.
- `--backend ollama`: the real model on the same cases. Only these numbers describe model quality.

## Adding a case
1. Create `src/penmunshi/eval/cases/<id>.json` (copy an existing one). Fields: `id`, `split` (dev|heldout), `title`, `asset`, `notes`, `tool_output`, `evidence[] {name, text, file?}`, `gold {vector, severity, cwe[], cves[], secrets[]}`, `seeded_secrets[]`, `faults {...}`.
2. Compute `gold.severity` from `gold.vector` with the `cvss` library. `tests/test_eval.py` fails if they disagree or if a seeded secret is not detectable.
3. Fictional targets only (`*.acme.test`). Fake secrets only (AWS documentation example keys, handmade JWTs).
4. For real screenshots: render text to PNG with `scripts/make_demo_screenshots.py` as a template, store under `eval/cases/assets/`, and set `evidence[].file` while keeping the ground-truth `text`. Add a blurry and a cropped variant of each; use Pillow `GaussianBlur` and crops.
5. Never add a case to `heldout` after you have looked at held-out results.

## Discipline
- Tune on dev. Run held-out once with the real model. The run is logged in `.penmunshi/heldout_runs.jsonl`; the post states how many times it ran and shows the first run.
- Never edit a number, never drop a bad case. Explain it in the failure log.
- n is small (12 cases): report counts next to percentages and do not claim statistical power.

## Failure taxonomy (use these labels in the log)
- **Wrong and calm**: a plausible but wrong digit, year, status code or host. Hardest to catch; the best material for the post.
- **Fabricated evidence**: a claim whose quote is not in the sources (caught by `claims.py`).
- **Hallucinated id**: a CVE/CWE nobody wrote (caught by `ids.py`).
- **Leak**: a secret reaching a prompt or the output (caught by masking; any leak is a P0 bug).
- **Format drift**: invalid JSON or missing fields (retry, then `draft_failed`).

## Reporting
1. Run the workflows in `.agent/workflows/eval-real.md`.
2. Paste the generated tables into `docs/EVAL.md` unedited; add one paragraph per failure: what the model did, whether the verifier caught it, what you changed.
3. Add machine specs, model tags, warm/cold timing note.
4. Anything you could not run goes to `HUMAN_TODO.md` as `TODO(human)`.
