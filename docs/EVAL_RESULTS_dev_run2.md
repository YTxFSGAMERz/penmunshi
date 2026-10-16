# PenMunshi eval results

- Backend: `ollama`; model: `gemma4:e4b`; split: `dev`; run: 2026-10-15 20:55 UTC

| Metric | dev |
|---|---|
| Cases | 22 |
| Severity matches gold (code-computed) | 32% (7/22) |
| Exact CVSS vector matches gold | 23% (5/22) |
| Right CWE found | 64% (14/22) |
| Seeded secret kinds detected | 100% |
| Seeded secrets leaked into prompts/outputs | 0 |
| CVE ids emitted without source in the notes | 0 |
| Real claims supported by their quote | 98% (48/49) |
| Injected faults caught | n/a (no faults injected) |
| Cases ready without human fixes | 91% (20/22) |
| Latency per finding p50 / p95 (ms) | 57465 / 81232 |

## Per case

| Case | Split | Severity | Gold ok | CWE ok | Faults caught | Status | ms |
|---|---|---|---|---|---|---|---|
| bac-role-tampering | dev | Medium | NO | yes | 0/0 | ready | 55683 |
| command-injection-ping | dev | High | yes | yes | 0/0 | ready | 58492 |
| cors-credentials | dev | High | NO | NO | 0/0 | ready | 55728 |
| csrf-account-email | dev | High | NO | yes | 0/0 | ready | 55576 |
| default-creds-admin | dev | Critical | yes | NO | 0/0 | ready | 59394 |
| exposed-git | dev | High | yes | NO | 0/0 | ready | 65584 |
| graphql-introspection | dev | High | NO | yes | 0/0 | ready | 55461 |
| hardcoded-secret-bundle | dev | Critical | NO | yes | 0/0 | needs_review | 57629 |
| idor-invoices | dev | High | NO | NO | 0/0 | ready | 68164 |
| info-disclosure-phpinfo | dev | High | NO | yes | 0/0 | ready | 81232 |
| insecure-deserialization | dev | Critical | yes | yes | 0/0 | ready | 57302 |
| login-no-rate-limit | dev | Critical | NO | NO | 0/0 | ready | 54156 |
| missing-hsts-header | dev | High | NO | NO | 0/0 | ready | 56255 |
| open-redirect-oauth | dev | High | NO | yes | 0/0 | ready | 60381 |
| outdated-jquery | dev | High | NO | yes | 0/0 | needs_review | 73669 |
| path-traversal-downloads | dev | High | yes | yes | 0/0 | ready | 52126 |
| reflected-xss-search | dev | Critical | NO | yes | 0/0 | ready | 52223 |
| sensitive-cookie-no-httponly | dev | High | NO | NO | 0/0 | ready | 82682 |
| sqli-login | dev | Critical | yes | yes | 0/0 | ready | 60022 |
| subdomain-takeover-cname | dev | Critical | NO | yes | 0/0 | ready | 64696 |
| weak-password-policy | dev | Critical | NO | yes | 0/0 | ready | 49904 |
| xxe-xml-upload | dev | High | yes | NO | 0/0 | ready | 54403 |

## Failures to explain in the write-up

- `bac-role-tampering`: severity Medium (gold differs), CWE ok, leaks 0
- `cors-credentials`: severity High (gold differs), CWE missing, leaks 0
- `csrf-account-email`: severity High (gold differs), CWE ok, leaks 0
- `default-creds-admin`: severity Critical (gold ok), CWE missing, leaks 0
- `exposed-git`: severity High (gold ok), CWE missing, leaks 0
- `graphql-introspection`: severity High (gold differs), CWE ok, leaks 0
- `hardcoded-secret-bundle`: severity Critical (gold differs), CWE ok, leaks 0
- `idor-invoices`: severity High (gold differs), CWE missing, leaks 0
- `info-disclosure-phpinfo`: severity High (gold differs), CWE ok, leaks 0
- `login-no-rate-limit`: severity Critical (gold differs), CWE missing, leaks 0
- `missing-hsts-header`: severity High (gold differs), CWE missing, leaks 0
- `open-redirect-oauth`: severity High (gold differs), CWE ok, leaks 0
- `outdated-jquery`: severity High (gold differs), CWE ok, leaks 0
- `reflected-xss-search`: severity Critical (gold differs), CWE ok, leaks 0
- `sensitive-cookie-no-httponly`: severity High (gold differs), CWE missing, leaks 0
- `subdomain-takeover-cname`: severity Critical (gold differs), CWE ok, leaks 0
- `weak-password-policy`: severity Critical (gold differs), CWE ok, leaks 0
- `xxe-xml-upload`: severity High (gold ok), CWE missing, leaks 0
