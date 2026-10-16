# DEV post outline

Writing quality is weighted most in the judging. Use the official **Side Hustle Submission Template** from the challenge page as the skeleton (re-read it before posting) and fill it with this structure. Only real numbers. Mark unknowns `TODO(human)` until you have them.

## Title (specific, with numbers)

`PenMunshi: an offline pentest report copilot where Gemma writes and code checks every fact (<N> cases, <M> injected faults caught, <T> s per finding on a 6 GB laptop GPU)`

Cover image: the UI showing one dashed underline (unsupported quote) and one black redaction bar.

## Sections

1. **The 30-second version.** What it is, who pays, what it costs to run. One paragraph, no adjectives.
2. **The problem.** Three sourced facts (below), then one sentence on the gap: testers lose days to reports and cannot paste findings into cloud AI.
3. **Demo.** 90-second video (`docs/DEMO_SCRIPT.md`) plus three screenshots: capture, verification checks, exported report.
4. **How it works.** The flow diagram and the "model proposes / code decides" table from the README. Explain *why* each fact moved to code.
5. **What I measured.** Dev and held-out tables, e2b vs e4b head-to-head, timing on your laptop. Then the failure log: show the failures first. The best Gemma write-up of the Weekend challenge led with a calm wrong answer it engineered out; do the same with your own.
6. **Why open matters here.** Numbered, concrete: (a) NDAs and client confidentiality; (b) works offline; (c) auditable: every check is code you can read; (d) Apache-2.0 weights, MIT code: no lock-in, no per-call bill; (e) a path to fine-tune on your own report style. Add one honest sentence on what a closed API would do better.
7. **The closest existing tools.** Be generous and exact: Dradis ships a local-Ollama feature (Echo), PentestReportAI, Cyver, PlexTrac. State your difference in one line: fully offline vision on screenshots + code-owned verification + published failure log. Verify each claim about a competitor before posting.
8. **My first user.** Who (role, not name unless they agree), what they ran, minutes saved (measured, n=...), a quote with permission, what they asked for next, whether they would pay and how much. If you only got feedback and not a payment, say so.
9. **Limits and next steps.** Misread digits, curated CWE subset, no pixel blur yet, v3.1 only.
10. **Partner technology.** Gemma (core, run locally). Mention `.tech` only if the project is live on a domain you claimed. Mention others only if genuinely used.
11. **Try it.** Repo, live page, license.

## Facts with sources (re-verify before citing)

- Reporting is 20 to 60 percent of project time: vendor whitepaper, so say "vendor-reported". https://www.bankinfosecurity.com/whitepapers/cut-pentest-reporting-time-by-50-or-more-automation-w-15449
- Engagement NDAs likely prohibit routing findings through third-party AI (Dradis, a competitor, so attribute it). https://dradis.com/academy/data-sovereignty/shadow-ai-pentest-data-leakage.html
- Indian VAPT is compliance-driven and priced per engagement (web app VAPT roughly 40k to 1.5L INR in 2026 per one vendor guide). https://www.tcsa.in/resources/vapt-cost-india-2026 and https://cybersecify.com/blog/what-is-vapt-explained/
- Competitors: https://dradis.com/articles/self-hosted-ai-pentest-reporting.html and https://www.pentestreportai.com/
- Judging and rules: https://dev.to/challenges/hacktoberfest-week2-2026-10-12 and https://dev.to/challenges/hf26
- What won the Weekend Gemma category (study the structure, do not copy): https://dev.to/uptimearchitect/gemma-4-reads-my-parents-mail-at-home-39-test-letters-9-of-them-real-and-one-calm-wrong-answer-3obf

## Numbers to fill (real runs only)

| Item | Value |
|---|---|
| Laptop, GPU, RAM | TODO(human) |
| Model(s) and quantisation | TODO(human) |
| Dev: severity match / CWE / claims supported | TODO(human) |
| Held-out (first run, how many runs total) | TODO(human) |
| p50 / p95 seconds per finding (e4b, e2b) | TODO(human) |
| First user: findings run, minutes before/after | TODO(human) |

## Honesty checklist

- Every number appears in `docs/EVAL.md` or a first-user note.
- Fake-backend numbers are labelled as verification-layer tests.
- You say what is not built yet.
- No competitor claim you have not checked.
- Quotes from people: permission obtained.
