---
name: five-day-sprint
description: The day-by-day plan and cut list for finishing PenMunshi before the Hacktoberfest Week 2 deadline (Oct 18 11:59 PM PDT, which is Oct 19 12:29 PM IST): daily gates, what to cut first when behind, and when to stop adding features. Use whenever you plan work, decide priorities, estimate effort, or the schedule slips.
---

# Five-day sprint

The plan with dates is `docs/DAY_PLAN.md` (Day 1 is Wed Oct 14, Day 5 is Sun Oct 18). **Gates beat features:** if a day's gate fails, fix it before adding anything new.

## Priority order (value per hour)
1. Real-model smoke run and the verification layer working on real output.
2. Eval with real numbers and an honest failure log (writing material).
3. One visible differentiator, finished and tested: screenshot auto-blur **or** claim-to-evidence highlighting.
4. First user session.
5. Demo video, landing/replay page on the .tech domain.
6. The post. Reserve Day 5 for it. Writing is weighted most.

## Cut list when behind (cut from the top)
1. CVSS v4, retest mode, importers, DOCX cover/TOC polish.
2. Sentry or any optional partner integration.
3. Static replay site (keep a plain landing page with the video).
4. Second differentiator.
Never cut: tests, the failure log, the held-out run, the first-user attempt, the post.

## If the real model is too slow
Measure first. Try the smaller Gemma variant, a smaller `PENMUNSHI_MAX_IMAGE_SIDE`, a shorter prompt. Say so honestly in the post: "batch job on a laptop" is still a valid side-hustle story.

## If there is no first user by Day 4
Run the session with one friend who writes reports and say exactly that. Do not invent a customer.

## Stop rule
Feature freeze at the start of Day 5 except bug fixes. Submit on the evening of Oct 18 IST; the morning of Oct 19 is buffer, not plan.
