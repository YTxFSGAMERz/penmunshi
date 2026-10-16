---
name: demo-video-90s
description: Storyboard, record and caption the 90-second PenMunshi demo video: shot list with timings, what must be real on screen, offline proof, recording and upload checklist. Use whenever you write or revise the demo script, prepare a recording, or choose which results to show on camera.
---

# Demo video (90 seconds)

The script and timings live in `docs/DEMO_SCRIPT.md`. This skill adds the rules that keep the video honest and watchable.

## Must be real
- The real model on a real run, with Wi-Fi visibly off. Offline is the proof of the product promise.
- A "catch" on screen (dashed underline, removed CVE, masked secret) must come from that run. If the model did not produce one, show the fault-injection eval output and say out loud that it is an injected fault.
- Numbers on the last card come from `docs/EVAL.md`, with n.

## Preparation checklist
- Use `examples/acme-demo` or lab material only. Hide bookmarks, tabs, notifications, usernames.
- Browser zoom 125 percent, 1080p, a calm theme, cursor highlighting on.
- Pre-warm the model so the first call is not a minute of silence (or show the elapsed counter and cut once, with a jump-cut label).
- Rehearse once; keep each beat to one sentence of caption. Captions instead of voice are fine.

## Output
Unlisted upload, embed in the DEV post, link in the README, and keep a 10-second GIF of the capture-to-draft moment for the cover.

## What the agent can do
Draft captions, produce a shot list from the current UI, create a `docs/assets/` screenshot set, and check the script against the real UI labels. Recording is a human task (`HUMAN_TODO.md`).
