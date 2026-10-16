---
name: ollama-gemma-local
description: Run, tune and debug the local Gemma 4 model through Ollama: model tags, structured JSON output, vision input, prompts, latency on a 6 GB laptop GPU, fallbacks, and error messages. Use whenever you touch src/penmunshi/llm/, change a prompt, see slow or empty or invalid model output, compare e2b with e4b, or run anything against the real model.
---

# Local Gemma with Ollama

## Setup
```
ollama pull gemma4:e4b        # vision-capable default
ollama list                   # check the exact tag names installed; if the small variant is named differently, use that
python -m penmunshi doctor    # Ollama reachable? model installed? GPU?
```
Settings are environment variables (see `.env.example`): `PENMUNSHI_MODEL`, `PENMUNSHI_OLLAMA_URL`, `PENMUNSHI_TIMEOUT`, `PENMUNSHI_NUM_CTX`, `PENMUNSHI_MAX_IMAGE_SIDE`.

## How the client works (`llm/ollama.py`)
- `POST /api/chat`, `stream:false`, `format` = a flat JSON schema (structured outputs), temperature 0.
- Images travel as base64 in the user message, downscaled first by `llm/images.py` (default longest side 1600 px).
- One retry on invalid JSON in the client, one more in `pipeline._draft_with_retry` with the validation error in the prompt. HTTP errors become `LLMError`, and the pipeline degrades instead of crashing (`vision_failed`, `draft_failed`).

## Speed on a small laptop GPU
The E4B file is about 6.6 GB, so on a 6 GB card some layers run on the CPU. Measure, do not guess:
```
python - <<'EOF'
import time
from penmunshi.llm import OllamaLLM
from penmunshi.llm.prompts import TRANSCRIBE_SYSTEM, TRANSCRIBE_USER, TRANSCRIBE_SCHEMA
img = open("examples/acme-demo/findings/002-exposed-git/evidence/config-history.png", "rb").read()
llm = OllamaLLM()
for i in range(3):
    t = time.perf_counter()
    out = llm.generate_json(system=TRANSCRIBE_SYSTEM, user=TRANSCRIBE_USER, schema=TRANSCRIBE_SCHEMA, images=[img])
    print(i, round(time.perf_counter() - t, 1), "s", len(out["transcript"]), "chars")
EOF
```
The first call includes model load. Report warm timings and say so. Tactics, in order: close other GPU apps; `PENMUNSHI_MAX_IMAGE_SIDE=1280`; lower `PENMUNSHI_NUM_CTX` when notes are short; keep Ollama warm; analyze one finding at a time; try the smaller Gemma variant and compare accuracy on the dev split, then report both rows.

## Quality levers, by payoff
1. Keep prompt rules few and sharp. Every rule in `prompts.py` must have a matching check in `verify/`; delete rules that have none.
2. Transcribe first, reason second (already the design). Never ask one call to read a screenshot and judge it.
3. Make the quote requirement concrete (verbatim, max 200 characters, name the source).
4. Add a few-shot example to `DRAFT_SYSTEM` only after dev shows a repeated failure, and keep it fictional.
5. Digits are the weak spot of small vision models. Add a deterministic cross-check (for example, status codes and numbers in the notes must appear in the transcript) before you add more prompting.

## Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `Ollama request failed: ... refused` | Ollama not running | `ollama serve` or open the Ollama app |
| doctor says model missing | not pulled or different tag | `ollama pull <tag>`; set `PENMUNSHI_MODEL` |
| timeout on the first call | model loading | raise `PENMUNSHI_TIMEOUT`, warm up once |
| `model returned invalid JSON` | schema not enforced or model drifted | check `format` is sent; lower `num_ctx` pressure; shorten notes |
| empty transcripts | image too small or too large | check `PENMUNSHI_MAX_IMAGE_SIDE`; view the downscaled bytes |
| answer text missing but tokens used | reasoning output eating the budget | check the raw `/api/chat` response for a thinking field and the model's options |
| very slow | CPU spill | see "Speed" above |

## Rules
- Never add a hosted API backend. Local is the product promise and the "why open" argument.
- Every results table records the model tag, quantisation, laptop specs and whether timings are warm.
- Gemma 4 weights are published under Apache 2.0 (verify on the model card before you state it in the post).
