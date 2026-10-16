# PenMunshi eval results

- Backend: `ollama`; model: `gemma4:e4b`; split: `dev`; run: 2026-10-15 20:32 UTC

| Metric | dev |
|---|---|
| Cases | 22 |
| Severity matches gold (code-computed) | 36% (8/22) |
| Exact CVSS vector matches gold | 23% (5/22) |
| Right CWE found | 64% (14/22) |
| Seeded secret kinds detected | 100% |
| Seeded secrets leaked into prompts/outputs | 0 |
| CVE ids emitted without source in the notes | 0 |
| Real claims supported by their quote | 98% (48/49) |
| Injected faults caught | n/a (no faults injected) |
| Cases ready without human fixes | 91% (20/22) |
| Latency per finding p50 / p95 (ms) | 55425 / 78422 |

## Per case

| Case | Split | Severity | Gold ok | CWE ok | Faults caught | Status | ms |
|---|---|---|---|---|---|---|---|
| bac-role-tampering | dev | High | yes | yes | 0/0 | ready | 62889 |
| command-injection-ping | dev | High | yes | yes | 0/0 | ready | 47563 |
| cors-credentials | dev | High | NO | NO | 0/0 | ready | 44267 |
| csrf-account-email | dev | High | NO | yes | 0/0 | ready | 48872 |
| default-creds-admin | dev | Critical | yes | NO | 0/0 | ready | 48395 |
| exposed-git | dev | High | yes | NO | 0/0 | ready | 57226 |
| graphql-introspection | dev | High | NO | yes | 0/0 | ready | 53497 |
| hardcoded-secret-bundle | dev | Critical | NO | yes | 0/0 | needs_review | 52279 |
| idor-invoices | dev | High | NO | NO | 0/0 | ready | 61319 |
| info-disclosure-phpinfo | dev | High | NO | yes | 0/0 | ready | 78422 |
| insecure-deserialization | dev | Critical | yes | yes | 0/0 | ready | 52128 |
| login-no-rate-limit | dev | Critical | NO | NO | 0/0 | ready | 54631 |
| missing-hsts-header | dev | High | NO | NO | 0/0 | ready | 56384 |
| open-redirect-oauth | dev | High | NO | yes | 0/0 | ready | 58812 |
| outdated-jquery | dev | High | NO | yes | 0/0 | needs_review | 73019 |
| path-traversal-downloads | dev | High | yes | yes | 0/0 | ready | 56219 |
| reflected-xss-search | dev | Critical | NO | yes | 0/0 | ready | 52428 |
| sensitive-cookie-no-httponly | dev | High | NO | NO | 0/0 | ready | 83654 |
| sqli-login | dev | Critical | yes | yes | 0/0 | ready | 60793 |
| subdomain-takeover-cname | dev | Critical | NO | yes | 0/0 | ready | 65203 |
| weak-password-policy | dev | Critical | NO | yes | 0/0 | ready | 50696 |
| xxe-xml-upload | dev | High | yes | NO | 0/0 | ready | 54324 |

## Failures to explain in the write-up

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
