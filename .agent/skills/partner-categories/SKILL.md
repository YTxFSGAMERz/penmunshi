---
name: partner-categories
description: Decide and document which DEV Hacktoberfest partner categories PenMunshi genuinely qualifies for (Gemma, .tech domain, Entire, GitHub Copilot or Actions, Sentry tracing, Tinker, hosting) and collect the evidence for each. Use whenever someone proposes adding a partner technology, writes the 'partner technology' paragraph, or asks how to improve the odds of a category prize.
---

# Partner categories

See `docs/CATEGORIES.md` (as read on the hub on Oct 13 2026). **Re-read the hub before claiming anything**: categories and wording can change.

## Rules of thumb
- Enter only what you genuinely use. A bolted-on integration reads as filler and can hurt the technical score. You can win only one prize per challenge, so extra entries are extra chances, not extra prizes.
- Partner categories come from smaller pools than the overall prize, which is why the cheap, genuine ones are worth doing.

## Status for this project
| Category | Fit | Action | Evidence |
|---|---|---|---|
| Gemma | core | already built; add the e2b vs e4b comparison and timings | eval tables, model tags, Apache-2.0 note |
| .tech domain | easy | human claims the free domain at hacktoberfest.com/my/promos; agent builds the landing/replay page | live URL in the post; domain screenshot |
| GitHub Actions / Copilot | partial | CI exists; claim Copilot only if Copilot was really used to build or review | Actions run link, PRs or sessions |
| Entire / agent sessions | optional | only if the human actually used it while building | embedded session link |
| Sentry tracing | optional | if built: opt-in, off by default, **metadata only** (latency, token counts), never finding text, because the product promise is that nothing leaves the laptop | traces or screenshots, setup note |
| Tinker (fine-tuning) | not in scope | skip unless a real fine-tune with a baseline comparison is done | n/a |
| Hosting partners | landing page only | never imply the hosted page runs the model | deploy link |

## The honest hosted page
The .tech page is a landing page plus a **recorded replay** generated from a real local run (`demo-data.json`). Label it "recorded replay" in the UI. Never connect it to a hosted model.

## Writing the paragraph
One short paragraph per category: what you used, how, and where the reader can see it. Link evidence. No adjectives.
