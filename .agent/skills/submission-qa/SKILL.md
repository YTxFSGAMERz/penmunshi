---
name: submission-qa
description: Final pre-submission checklist for the PenMunshi repo and DEV post: rules compliance (new repo started in the challenge window), secrets scan, license, README, CI, honest numbers, links, template sections, tags, categories and what is still the human's to do. Use before publishing the post, tagging a release, or whenever someone says the project is done.
---

# Submission QA

Walk this top to bottom and paste the real output of each command into your final message. Do not tick a box from memory.

## Rules and eligibility
- [ ] Repo was created inside the challenge window (first commit on or after Oct 12 2026) and is public.
- [ ] Prior work is credited (libraries, the `cvss` package, any code or ideas you reused).
- [ ] The post is in English, follows the official Side Hustle Submission Template, and uses the tags the challenge page lists.
- [ ] Submitted before Oct 18 11:59 PM PDT (= Oct 19 12:29 PM IST).

## Repo
- [ ] `ruff check .` clean. `python -m pytest -q` all green. `python -m penmunshi eval --backend fake` shows every injected fault caught and zero leaks.
- [ ] `python -m penmunshi scan .` reports hits only in fake-data locations (`tests/`, `examples/`, `src/penmunshi/eval/cases/`, `scripts/make_demo_screenshots.py`, skill docs that show example patterns), and every hit is a documented fake value (AWS documentation example keys, handmade JWTs, fictional emails). Anything else is a leak: fix it before anything else.
- [ ] No real client material, no `.env`, no `out/` outputs, no personal paths or tokens in docs or screenshots.
- [ ] README quickstart works on a clean clone (try it in a fresh virtualenv). LICENSE present. Limits section present.
- [ ] CI is green on the default branch. Badge optional.

## Numbers and claims
- [ ] Every number in README and post appears in `docs/EVAL.md` or the first-user notes. Held-out run count stated.
- [ ] Fake-backend results are labelled as verification-layer tests everywhere.
- [ ] Competitor statements verified (Dradis Echo, PentestReportAI, Cyver, PlexTrac). Vendor statistics labelled as vendor-reported.
- [ ] Gemma license statement checked against the model card.

## Post
- [ ] Title specific with numbers. Cover image shows the product's one trick. Video embedded and linked. Alt text on images.
- [ ] Failure log shown. Limitations stated. "Why open matters" is numbered and concrete. First-user section only contains real events.
- [ ] Category paragraphs only for categories genuinely used. .tech page is live if claimed, and labelled as a replay.
- [ ] One cold reader summarised it correctly in two sentences.

## Hand-off
List every open `TODO(human)` from `HUMAN_TODO.md` so the author sees what is still theirs.
