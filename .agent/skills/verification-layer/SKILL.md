---
name: verification-layer
description: How to change or extend the deterministic checks in src/penmunshi/verify: CVSS maths, CVE/CWE provenance, claim quote checks, secret and PII detectors with checksums, masking and lint rules. Use whenever you touch verify/, add a detector or lint rule, see a model failure that code could have caught, or are tempted to trust model output for a fact.
---

# Verification layer

Everything in `src/penmunshi/verify/` is deterministic: no model calls, no network, no randomness. That is what makes it testable and what the write-up can honestly brag about.

## Workflow for any change
1. Read the existing tests for the style: one positive, one near-miss, one "never leaks" (`tests/test_secrets.py`, `test_ids.py`, `test_claims.py`, `test_lint.py`).
2. Write the failing test first, run it, then change code.
3. If the change should catch a real model failure, add a fault to an eval case (`faults` in `eval/cases/*.json`) and a branch in `eval/harness.py::run_case`, so the fault-injection run proves it on every push.

## Components
| File | Owns | Pitfalls |
|---|---|---|
| `cvss.py` | vector build, score, severity band, tester vector detection | invalid letters give `None` and the finding is `Unrated` (never guess). 0.0 is "None" (informational) |
| `ids.py` | CVE provenance, CWE catalog check | years above current+1 are implausible; dedupe; the raw id stays in `removed_ids` |
| `claims.py` | quote-or-it-didn't-happen | min 8 characters; fuzzy threshold 0.85; a wrong-source citation is corrected, not punished |
| `secrets.py` | detectors, validators, masking | detector order is priority; previews never contain the full value; placeholders (`****`, `<redacted>`) are ignored |
| `lint.py` | report-quality rules | every rule needs a code, a level (error/warn/info) and a human sentence |
| `catalog.py` | CWE subset and KEV | the bundled KEV is a sample; the real list comes from `scripts/update_kev.py` |

## Rules that cost us a bug
- **Mask by pattern AND by exact value.** A model can repeat a bare password that no regex recognises. The pipeline remembers values it saw in the input (`known_values`, minimum length 6) and masks them in the output. See `docs/EVAL.md`, failure #1.
- **Validators beat regex alone:** Aadhaar (Verhoeff), cards (Luhn), PAN (entity letter), AWS ids by prefix. Add one whenever the format has a checksum.
- **Never store raw secrets** in `VerifiedFinding`. `SecretPublic.preview` is masked (`ab******` or `**** 1234`).
- **Specific beats generic** when spans overlap (`password=AKIA...` is an AWS key).
- **Check the checker.** When a metric says "missed", first ask whether the harness is wrong (failure #2).
- **Bound your regexes.** No unbounded `[\s\S]*` on user text. Use `{0,6000}`.

## Adding a lint rule
Edit `verify/lint.py`, add a test, decide whether it changes `status` (errors do; warnings and info do not), and mention it in `docs/ARCHITECTURE.md` if it is user-visible.

## Do not
- Call the model from `verify/`.
- Loosen a check to make a test pass. Ask whether the model or the check is wrong.
- Add a CVE "lookup" that needs internet at report time. Offline enrichment only (bundled or pre-downloaded data).
