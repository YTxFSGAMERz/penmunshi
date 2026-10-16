---
name: screenshot-redaction
description: Implement and test pixel-level redaction of secrets and PII in screenshots: OCR to find text boxes, map secret spans to boxes, paint opaque bars, verify the secret is unrecoverable, show a before/after preview in the UI, and embed only redacted images in reports. Use whenever a task mentions auto-blur, redaction of images, embedding screenshots in the report, or client-safe export.
---

# Screenshot redaction

Today the vision pass transcribes screenshots and the UI/report show masked *text*. Pentest reports normally embed the screenshots themselves, so pixel redaction is the biggest "client-safe by default" upgrade. Treat it as a security feature: a miss leaks a credential.

## Design
1. **OCR with boxes.** Prefer `rapidocr-onnxruntime` (pip install, CPU, works offline after install, friendly on Windows). Tesseract is an alternative if the binary is present. Keep it an optional extra (`pip install -e ".[ocr]"`) and degrade with a clear message when missing.
2. **Find secrets in OCR text.** Join OCR lines with newlines, keep each line's character offset, run `verify/secrets.scan_text` on the joined text. Also run the exact `known_values` from the pipeline (values already seen in notes/transcripts).
3. **Map spans to boxes.** A hit inside one OCR line covers that line's box; shrink it proportionally to the character span when the engine only returns line boxes; use word boxes when available. Pad by 4 px.
4. **Paint opaque bars.** Solid fill, never blur or pixelate: those can be partially reversed.
5. **Verify.** Re-OCR the redacted image and assert none of the secret strings is recoverable. If any survives, fall back to blacking out the whole line and set a lint warning.
6. **Never keep the original in memory longer than needed or on disk at all.** Only the redacted PNG is stored, shown, embedded in HTML (data URI) or DOCX.

## Tests (model-free)
- Render synthetic screenshots with Pillow (see `scripts/make_demo_screenshots.py`) containing the fake AWS pair, a JWT, `password=...`, an email and an Aadhaar number built with `verhoeff.check_digit`.
- Assert: bars cover the right pixels (sample pixel colours inside and outside), the re-OCR check passes, non-secret text is untouched, and a case with no secrets returns identical pixels.
- Skip OCR tests with `pytest.importorskip("rapidocr_onnxruntime")` so CI stays green without the extra, but run them locally and say so in the PR.

## UI
- In the draft view add a "Screenshots" section with a before/after toggle. "Before" shows only the *redacted* image with the bars highlighted by a 2 px outline; the original never reaches the browser.
- Counts ("3 regions masked") use the same words as the transcript secrets list.

## Do not
- Do not blur. Do not trust a single OCR pass for safety claims. Do not claim "guaranteed" in docs: say what was checked and how.
