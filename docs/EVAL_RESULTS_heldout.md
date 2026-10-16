# PenMunshi eval results

- Backend: `ollama`; model: `gemma4:e4b`; split: `heldout`; run: 2026-10-15 21:03 UTC

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
| Injected faults caught | n/a (no faults injected) |
| Cases ready without human fixes | 100% (8/8) |
| Latency per finding p50 / p95 (ms) | 57955 / 66894 |

## Per case

| Case | Split | Severity | Gold ok | CWE ok | Faults caught | Status | ms |
|---|---|---|---|---|---|---|---|
| clickjacking-iframe | heldout | Medium | yes | NO | 0/0 | ready | 53074 |
| crlf-injection-headers | heldout | Critical | NO | NO | 0/0 | ready | 56556 |
| dir-listing-backups | heldout | High | yes | NO | 0/0 | ready | 63348 |
| jwt-none-alg | heldout | Critical | NO | yes | 0/0 | ready | 66894 |
| nosql-injection-auth | heldout | Critical | yes | NO | 0/0 | ready | 59289 |
| race-condition-coupon | heldout | High | NO | yes | 0/0 | ready | 51886 |
| ssrf-image-fetch | heldout | Critical | yes | yes | 0/0 | ready | 66135 |
| stored-xss-profile | heldout | Critical | NO | yes | 0/0 | ready | 56622 |

## Failures to explain in the write-up

- `clickjacking-iframe`: severity Medium (gold ok), CWE missing, leaks 0
- `crlf-injection-headers`: severity Critical (gold differs), CWE missing, leaks 0
- `dir-listing-backups`: severity High (gold ok), CWE missing, leaks 0
- `jwt-none-alg`: severity Critical (gold differs), CWE ok, leaks 0
- `nosql-injection-auth`: severity Critical (gold ok), CWE missing, leaks 0
- `race-condition-coupon`: severity High (gold differs), CWE ok, leaks 0
- `stored-xss-profile`: severity Critical (gold differs), CWE ok, leaks 0
