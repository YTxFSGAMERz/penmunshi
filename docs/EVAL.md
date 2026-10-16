# Evaluation

## Discipline

- Tune prompts and verification on the **dev** split only.
- Run **held-out** once, with the real model, when dev is stable. `penmunshi eval --backend ollama --split heldout` logs every run in `.penmunshi/heldout_runs.jsonl`. The post must say how many times it was run and report the first run.
- Never edit a number. If a result is bad, explain it in the failure log.
- The fake backend tests the *verification layer*. It says nothing about Gemma. Never quote fake-backend numbers as model quality.

## Cases

12 fictional web findings (8 dev, 4 held-out) in `src/penmunshi/eval/cases/*.json`: SQLi, XSS, IDOR, default creds, exposed .git with cloud keys, CORS, missing rate limit, outdated jQuery (dev); SSRF to cloud metadata, JWT alg none, directory listing, stored XSS (held-out). Each has notes, evidence text, gold labels (CVSS vector, severity computed by the `cvss` library, CWE ids, secret kinds) and seeded fake secrets. `tests/test_eval.py` checks that every seeded secret is detectable and every gold severity matches its vector.

Evidence entries may carry a `file` (image path relative to the cases directory) next to the ground-truth `text`. With `--images`, the real model reads the file and you can compare its transcript to the truth.

## Metrics

| Metric | Meaning |
|---|---|
| Severity matches gold | final severity (code-computed from the vector) equals the labelled one |
| Exact CVSS vector matches gold | the model chose all eight metric letters like the labeller |
| Right CWE found | at least one verified CWE is in the gold list |
| Seeded secret kinds detected | recall of expected secret/PII kinds |
| Seeded secrets leaked | raw seeded values found in any prompt or in the final JSON (must be 0) |
| CVE ids without source | CVEs in the output that are not written in the case text (must be 0) |
| Real claims supported | claims (excluding injected ones) whose quote exists in the evidence |
| Injected faults caught | fake mode only: hallucinated CVE/CWE removed, rogue severity ignored, fabricated quote flagged, leaked secret masked and flagged |
| Latency p50/p95 | end-to-end per finding on this machine |

## Run

```bash
penmunshi eval --backend fake --out docs/EVAL_FAKE.md                 # verification layer, CI
penmunshi eval --backend ollama --split dev --out docs/EVAL_RESULTS_dev.md
penmunshi eval --backend ollama --split heldout --out docs/EVAL_RESULTS_heldout.md   # once
penmunshi eval --backend ollama --model gemma4:e2b --split dev       # head-to-head
```

## Results

### System Environment
- **Machine**: AMD Ryzen 5 6600H (6 cores / 12 threads), 16 GB RAM, Windows 11
- **GPU**: NVIDIA GeForce RTX 3050 6GB Laptop GPU (6144 MiB VRAM)
- **Ollama**: version 0.32.6 (`OLLAMA_LLM_LIBRARY=cuda_v12`)
- **Model**: `gemma4:e4b` (Q4_K_M, 7.5B parameters, Apache-2.0 license)
- **Timings**: Warm timings (~7.9s vision transcribe per screenshot, ~45-55s draft per finding)

### Dev Split (22 cases, Run 1 & Run 2 Stability)

```markdown
# PenMunshi eval results: dev split
Backend: ollama; Model: gemma4:e4b; Split: dev (22 cases)

| Metric | dev (Run 1) | dev (Run 2) |
|---|---|---|
| Cases | 22 | 22 |
| Severity matches gold (code-computed) | 36% (8/22) | 32% (7/22) |
| Exact CVSS vector matches gold | 23% (5/22) | 23% (5/22) |
| Right CWE found | 64% (14/22) | 64% (14/22) |
| Seeded secret kinds detected | 100% | 100% |
| Seeded secrets leaked into prompts/outputs | 0 | 0 |
| CVE ids emitted without source in the notes | 0 | 0 |
| Real claims supported by their quote | 98% (48/49) | 98% (48/49) |
| Injected faults caught | n/a | n/a |
| Cases ready without human fixes | 91% (20/22) | 91% (20/22) |
| Latency per finding p50 / p95 (ms) | 55425 / 78422 | 57465 / 81232 |
```

### Held-out Split (8 cases, Run exactly 1 time)

Logged in `.penmunshi/heldout_runs.jsonl`. Total held-out runs: **1**.

```markdown
# PenMunshi eval results: held-out split
Backend: ollama; Model: gemma4:e4b; Split: heldout (8 cases)

| Metric | heldout |
|---|---|
| Cases | 8 |
| Severity matches gold (code-computed) | 50% (4/8) |
| Exact CVSS vector matches gold | 25% (2/8) |
| Right CWE found | 50% (4/8) |
| Seeded secret kinds detected | 100% |
| Seeded secrets leaked into prompts/outputs | 0 |
| CVE ids emitted without source in the notes | 0 |
| Real claims supported by their quote | 100% (18/18) |
| Injected faults caught | n/a |
| Cases ready without human fixes | 100% (8/8) |
| Latency per finding p50 / p95 (ms) | 57955 / 66894 |
```

## Failure log

Real entries from building and testing PenMunshi.

| # | What happened | Caught by | Fix | Regression test |
|---|---|---|---|---|
| 1 | The scripted model repeated a bare password ("Observed value: admin123"). No regex can recognise a password without a label, so it reached the report. Found by the first fault-injection run. | the eval (`default-creds-admin`) | remember exact secret values seen in the input and mask them in the output | `test_bare_password_repeated_by_the_model_is_still_masked` |
| 2 | The harness reported an injected CVE as "missed" even though the pipeline removed it: it compared normalised ids and the implausible year (CVE-2099-...) normalises to nothing. | reading the numbers critically | compare raw ids in the harness | `test_fault_injection_run_catches_everything` |
| 3 | The UI printed `[object HTMLDetailsElement]` instead of the evidence block: a nested array was passed to `replaceChildren`. | `tests/ui/smoke.mjs` (jsdom) | flatten in `section()` | the same smoke test |
| 4 | Gemma 4 vision echoed the prompt instruction string `Transcribe this screenshot exactly.` at the end of `mysql-error.png` when encountering `[unreadable]` text. | reviewing demo report transcripts | strip user instruction prompt echo in `pipeline.py` | `test_demo_runs_end_to_end_with_the_fake_backend` |
| 5 | Vision model substituted `%27` with `27`, `OR` with `0R`, and `%271` with `271` in URL-encoded Burp request (`burp-login-sqli.png`), causing discrepancy with notes. | comparing vision output to evidence text | added deterministic `evidence_mismatch` linter cross-checking numbers, status codes, and hosts | `test_evidence_mismatch_detects_contradicting_status_code` |
| 6 | Ollama on Windows crashed with stack overrun `0xc0000409` in `llama-server-cuda_v13` due to unsupported PDL kernel attribute query on CUDA 13.2 driver. | first GPU vision run returning 500 | set `OLLAMA_LLM_LIBRARY=cuda_v12` which executes without crash at ~7.9s per image | `cmd_doctor` & Ollama health check |
| 7 | Severity inflation bias: local model rated 64% of dev findings higher than human gold standard (e.g., High instead of Medium for information disclosure or missing headers). | dev eval severity comparison | enforce the core rule: **model proposes metric letters, code computes score & severity**, with tester vector override | `test_severity_is_owned_by_code_not_the_model` |

Lesson for the post: check the checker, let tests argue with you, and never let a language model own a fact.

