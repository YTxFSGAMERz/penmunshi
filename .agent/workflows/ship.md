---
description: Pre-submission QA for the DEV challenge post and the repo
---

1. Load the `submission-qa` skill and walk its checklist top to bottom.
2. Run `penmunshi scan .`. Hits are allowed only in fake-data locations (`tests/`, `examples/`, eval cases, the demo-screenshot script, skill docs) and must be documented fake values. Fix anything else immediately.
3. Run the `/verify` workflow and paste the real output into the final message.
4. List every open `TODO(human)` from `HUMAN_TODO.md` so the author sees what is still theirs to do.
