---
description: Run lint, tests, the fault-injection eval and the UI smoke test
---

1. Run `ruff check .` and fix every finding.
2. Run `python -m pytest -q` and fix failures (never delete or weaken a test to make it pass).
3. Run `python -m penmunshi eval --backend fake` and confirm: injected faults caught 100%, secrets leaked 0, severity matches gold 100%.
4. If the UI changed: start `python -m penmunshi serve --backend fake --port 8765`, then in `tests/ui` run `npm i jsdom` once and `node smoke.mjs`. Stop the server afterwards.
5. Report the exact counts you saw. Do not summarise from memory.
