---
name: ui-polish-offline
description: Design and verify the offline PenMunshi web UI (src/penmunshi/web/index.html): visual language, design tokens, states, accessibility, XSS-safe DOM building, jsdom smoke tests and browser screenshots for the write-up. Use whenever you change the UI, add a screen, fix a UI bug, capture screenshots for the README or post, or are tempted to add a frontend framework or a CDN asset.
---

# UI polish (offline)

The UI is one HTML file served by FastAPI. No build step, no framework, no CDN: it must work with Wi-Fi off, and the demo video proves it.

## Visual language (keep it consistent)
- Verification is the design: **solid underline = quote found**, **dashed underline = not found**, **black bar = masked secret**. Always pair colour with a text label.
- Palette (CSS variables in `:root`, dark values under `prefers-color-scheme`): cool paper `--sheet`, document `--doc`, ink `--ink`, pen-blue `--pen`, green `--ok`, amber `--warn`, crimson `--bad`, severity colours `--crit/--high/--med/--low`.
- Type: serif headings (Iowan/Palatino/Georgia stack), system sans for text, Cascadia/Consolas for evidence only.
- Avoid: gradient decoration, icon circles, all-caps eyebrow labels, accent-striped cards, monospace for ordinary labels.

## Safety rules
- Build DOM with `h(tag, attrs, ...kids)` (text nodes only). Evidence and transcripts are attacker-controlled strings.
- Keep everything in memory. No `localStorage`, no cookies. The `beforeunload` guard warns when the basket is not empty.
- All requests go to the same origin. Never add `fetch` to a third-party URL.

## States to design for every screen
empty, loading (elapsed seconds, because the first call loads the model), error (say what to do next), success, partial (`needs_review`). Test keyboard-only use: Ctrl/Cmd+Enter analyzes, drop zone is focusable, focus rings visible. Respect `prefers-reduced-motion`.

## Upgrade ideas, by value
1. Click a claim to open the evidence transcript with the quote highlighted (the API already returns `found_in`; add character offsets).
2. Redaction preview (see `screenshot-redaction`).
3. Report preview pane that renders `/api/export?fmt=html` in an iframe sandbox.
4. Basket drag-to-reorder and per-finding status edits (tester overrides: severity vector, title).

## Verify before you say "done"
```
python -m penmunshi serve --backend fake --port 8765 &
cd tests/ui && npm i jsdom && node smoke.mjs     # all lines must say PASS
```
Add a check to `smoke.mjs` for every new interactive element. A past bug (array passed to `replaceChildren`) was only found this way.

## Screenshots for the post
With the Antigravity browser tool, load `http://127.0.0.1:8765` at 1280x800 and 390x844, run the real model on `examples/acme-demo`, and save PNGs to `docs/assets/`. Capture: capture screen, draft with checks table (one dashed underline), masked secrets, exported report. Use fictional data only.
