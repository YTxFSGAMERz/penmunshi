# PenMunshi eval results

- Backend: `fake`; model: `fake:scripted`; split: `all`; run: 2026-10-15 20:11 UTC
- **Fake backend:** a scripted stand-in drafts each case and injects faults. These numbers test the verification layer only. They say nothing about Gemma.

| Metric | dev | heldout |
|---|---|---|
| Cases | 22 | 8 |
| Severity matches gold (code-computed) | 100% (22/22) | 100% (8/8) |
| Exact CVSS vector matches gold | 100% (22/22) | 100% (8/8) |
| Right CWE found | 100% (22/22) | 100% (8/8) |
| Seeded secret kinds detected | 100% | 100% |
| Seeded secrets leaked into prompts/outputs | 0 | 0 |
| CVE ids emitted without source in the notes | 0 | 0 |
| Real claims supported by their quote | 100% (22/22) | 100% (8/8) |
| Injected faults caught | 100% (72/72) | 100% (26/26) |
| Faulted cases sent to human review (expected: all) | 100% (22/22) | 100% (8/8) |
| Latency per finding p50 / p95 (ms) | 11 / 23 | 10 / 16 |

## Per case

| Case | Split | Severity | Gold ok | CWE ok | Faults caught | Status | ms |
|---|---|---|---|---|---|---|---|
| bac-role-tampering | dev | High | yes | yes | 4/4 | needs_review | 23 |
| clickjacking-iframe | heldout | Medium | yes | yes | 3/3 | needs_review | 11 |
| command-injection-ping | dev | High | yes | yes | 3/3 | needs_review | 15 |
| cors-credentials | dev | Medium | yes | yes | 3/3 | needs_review | 17 |
| crlf-injection-headers | heldout | Medium | yes | yes | 3/3 | needs_review | 10 |
| csrf-account-email | dev | Medium | yes | yes | 3/3 | needs_review | 13 |
| default-creds-admin | dev | Critical | yes | yes | 4/4 | needs_review | 23 |
| dir-listing-backups | heldout | High | yes | yes | 3/3 | needs_review | 12 |
| exposed-git | dev | High | yes | yes | 4/4 | needs_review | 14 |
| graphql-introspection | dev | Medium | yes | yes | 3/3 | needs_review | 15 |
| hardcoded-secret-bundle | dev | High | yes | yes | 4/4 | needs_review | 11 |
| idor-invoices | dev | Medium | yes | yes | 3/3 | needs_review | 17 |
| info-disclosure-phpinfo | dev | Medium | yes | yes | 3/3 | needs_review | 14 |
| insecure-deserialization | dev | Critical | yes | yes | 3/3 | needs_review | 9 |
| jwt-none-alg | heldout | High | yes | yes | 4/4 | needs_review | 16 |
| login-no-rate-limit | dev | Medium | yes | yes | 3/3 | needs_review | 11 |
| missing-hsts-header | dev | Low | yes | yes | 3/3 | needs_review | 7 |
| nosql-injection-auth | heldout | Critical | yes | yes | 3/3 | needs_review | 9 |
| open-redirect-oauth | dev | Medium | yes | yes | 3/3 | needs_review | 8 |
| outdated-jquery | dev | Medium | yes | yes | 4/4 | needs_review | 10 |
| path-traversal-downloads | dev | High | yes | yes | 3/3 | needs_review | 11 |
| race-condition-coupon | heldout | Medium | yes | yes | 3/3 | needs_review | 9 |
| reflected-xss-search | dev | Medium | yes | yes | 3/3 | needs_review | 11 |
| sensitive-cookie-no-httponly | dev | Medium | yes | yes | 3/3 | needs_review | 7 |
| sqli-login | dev | Critical | yes | yes | 4/4 | needs_review | 15 |
| ssrf-image-fetch | heldout | Critical | yes | yes | 4/4 | needs_review | 11 |
| stored-xss-profile | heldout | Medium | yes | yes | 3/3 | needs_review | 10 |
| subdomain-takeover-cname | dev | High | yes | yes | 3/3 | needs_review | 9 |
| weak-password-policy | dev | Medium | yes | yes | 3/3 | needs_review | 7 |
| xxe-xml-upload | dev | High | yes | yes | 3/3 | needs_review | 10 |
