# 90-second demo script

Record the real model, offline. Turn Wi-Fi off before the take: it is the proof.

| Time | Show | Say (one line each) |
|---|---|---|
| 0:00 to 0:08 | A messy notes file and a screenshot of a Burp response | "A pentest report takes days, and you cannot paste client findings into a cloud chatbot." |
| 0:08 to 0:25 | Wi-Fi icon off. Drop the screenshot into the UI, paste notes, press Analyze finding. Show the elapsed-seconds line. | "PenMunshi runs Gemma locally through Ollama. This is a laptop with no network." |
| 0:25 to 0:45 | The draft: severity chip and the vector with "computed by software" | "The model picked the metric letters. The score and severity come from code." |
| 0:45 to 1:00 | Evidence checks table: a solid underline (found) and a dashed one (not found) | "Every statement has to quote the evidence. This one did not, so it is flagged." |
| 1:00 to 1:12 | The black redaction bars and the "Masked before the model saw it" list | "Passwords and keys are masked before the model sees anything." |
| 1:12 to 1:22 | Export Word, open it, scroll to the verification appendix | "The report ships with a log of everything the software checked or changed." |
| 1:22 to 1:30 | Eval table (real numbers) + repo + live page | "<N> cases, <X> percent severity match, zero secrets leaked. Code is MIT." |

## Rules

- A "catch" on screen must be real. If the model did not hallucinate a CVE on camera, show the fault-injection eval output and say it is an injected fault.
- Use only fictional data (`shop.acme.test`). No personal tabs, no real client names.
- 1080p, large font (browser zoom 125 percent), no music needed, captions for the one-liners.
- Upload as unlisted video, embed in the DEV post, and also link it in the README.
