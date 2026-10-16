---
name: first-user-validation
description: Plan outreach, run sessions and record results for PenMunshi's first user (the challenge awards bonus points for a real first user): who to contact, DM templates, a 15-minute session script, what to measure, how to ask about price, ethics, and how to report it honestly. Use whenever you write outreach, prepare a user session, summarise user feedback, or write the 'My first user' section of the post.
---

# First-user validation

A real conversation beats a polished feature. Judges ask: did someone use it, did they pay or would they, what did they ask for next? Full scripts are in `docs/FIRST_USER.md`; keep that file as the single source of truth and update it, do not fork it.

## Who
Freelance pentesters, bug-bounty hunters who write reports, VAPT consultants at small firms, mentors of security clubs. Contact people the author already knows first (club, Discord, class). Aim for 8 to 10 messages, expect 2 sessions.

## What the agent can do
- Tailor DM templates to a named community (ask the human for the channel and the tone).
- Prepare a clean, fictional-data demo and a sanitized sample finding the person can swap for their own.
- Build the capture sheet (table in `docs/FIRST_USER.md`) and fill it from notes the human pastes in.
- Draft the "My first user" section **only from the capture sheet**. Quote only with permission. Say how many people, what they ran, what they corrected, what they asked for next, what price (if any) they named.

## What the agent must not do
- Do not contact anyone, post anywhere, or create accounts. Outreach is a human task: list it in `HUMAN_TODO.md`.
- Do not invent users, quotes, savings or willingness to pay. If there is no session yet, write `TODO(human)`.
- Do not ask for or store real client reports. Sanitized or lab findings only; nothing from a session is committed.

## Metrics worth capturing
Minutes to write a finding by hand vs with the tool (including their edits), count and kind of corrections, whether they would run it on client data, price named, next feature requested. Report n honestly.

## Product changes from feedback
Turn each repeated complaint into an issue labelled `from-user`, fix the top one before submission, and mention it in the post ("they asked for X, I shipped it in Y minutes"). This is the strongest paragraph a Side Hustle post can have.
