---
name: dev-post-writer
description: Write and edit the DEV submission post, README pitch, video captions and any judge-facing text for the Hacktoberfest Open-Source AI Challenge Week 2 (Side Hustle). Covers the judging criteria, the structure that won the Weekend Gemma category, style rules, honesty rules and a pre-publish checklist. Use whenever you draft or revise the post, summarise results for readers, or write any claim about performance, users or competitors.
---

# DEV post writer

Judging (from the challenge page): **writing quality is weighted most**, then relevance to the theme (open-weight or open-source AI at the core, something someone would actually pay for), creativity, technical execution, and optional partner technology. Tell readers why open matters for *this* build and, if you have one, how the first user went. A great project with a thin write-up does not win.

## Structure that works
Follow `docs/POST_OUTLINE.md` and map it to the official Side Hustle Submission Template (re-read it before posting). Read `references/winner-patterns.md` for what the Weekend winners did.

## Style rules
- Lead with the result and the person, not the stack. First paragraph answers: what is it, who pays, what does it cost to run.
- Numbers in tables, with n. Counts next to percentages. Warm vs cold timings labelled.
- **Failures first.** Show the wrong answers and what you changed. Readers trust a post that argues with itself.
- Short paragraphs, plain verbs, concrete nouns. No hype adjectives, no "revolutionary", no "seamless". Cut every sentence that would survive a find-and-replace of the product name.
- Say what you did not build. A limitations section is a credibility feature.
- Name competitors fairly and verify every claim about them.
- Images get alt text. Code blocks are runnable. The video is embedded and also linked.

## Honesty rules (hard)
- Every number comes from a real run recorded in `docs/EVAL.md` or a first-user note. Fake-backend numbers are labelled "verification-layer test".
- No invented users, quotes or traction. "Two testers tried it" is a valid result. "Would pay" is not "paid".
- Do not cite a source you have not opened. Mark vendor-reported statistics as vendor-reported.
- If something is unknown, write `TODO(human)` and list it in `HUMAN_TODO.md`.

## Before publishing
- Cold read by one person who has not seen the project: can they explain it back in two sentences?
- Title has a specific outcome and numbers. Cover image shows the product doing its one trick.
- Tags as the challenge page asks. Repo and live page linked. License stated. Partner categories claimed only where genuinely used.
- Optional but helpful: embed or link the agent session(s) you built it with (the challenge encourages "show your work").
