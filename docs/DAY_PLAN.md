# Five-day plan (Oct 14 to Oct 18)

Starting later than Oct 14? Keep the order and the gates, and cut from the top of the cut list in `.agent/skills/five-day-sprint/SKILL.md`. Count the days left until Oct 19, 12:29 PM IST and drop scope, not tests.

Deadline: Oct 18 23:59 PDT = Oct 19 12:29 PM IST. Submit on the evening of Oct 18 IST. Each day ends with a gate: if the gate fails, fix it before adding features.

## Day 1, Wed Oct 14: foundation and the real model
- Push the repo (first commit today). Claim the .tech domain.
- `pip install -e ".[dev]"`, `pytest`, `ruff check .` green on your machine.
- `penmunshi doctor`, then `penmunshi analyze examples/acme-demo --out out/demo-real`. Record timings.
- DM 8 to 10 testers.
- **Gate:** the demo report opens in a browser and every finding's transcript matches its screenshot. Misses logged in `docs/EVAL.md`.

## Day 2, Thu Oct 15: make it hard to fool
- Fix what Day 1 exposed (prompts, schema, timeouts). Run `/eval-real` on dev.
- Add 6 to 10 cases with real rendered screenshots and one blurry variant each.
- **Gate:** dev numbers stable across two runs; zero secrets leaked.

## Day 3, Fri Oct 16: the differentiator
- Screenshot auto-blur (OCR boxes) with a preview in the UI, or claim-to-evidence highlighting. Pick one, finish it, test it.
- First-user session #1.
- **Gate:** the feature has tests and a screenshot for the post.

## Day 4, Sat Oct 17: polish and proof
- Run held-out once. Record the e2b vs e4b table.
- Record the demo video offline. Capture UI screenshots.
- Deploy the landing/replay page on the .tech domain. Label it as a replay.
- **Gate:** README and EVAL.md contain real numbers only.

## Day 5, Sun Oct 18: write and ship
- Write the post from `docs/POST_OUTLINE.md`; failures first. Get one person to read it cold.
- `/ship` workflow. Publish with the challenge tags. Submit.
- **Gate:** post is live and linked from the challenge page before Oct 18 night IST.
