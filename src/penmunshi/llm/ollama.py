"""Minimal Ollama client: /api/chat with images and JSON-schema structured output."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Sequence

import httpx

from ..config import Settings
from .base import LLMError


def _extract_json(text: str) -> dict:
    text = text.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        value = json.loads(m.group(0))
    if not isinstance(value, dict):
        raise json.JSONDecodeError("expected a JSON object", text, 0)
    return value


class OllamaLLM:
    def __init__(self, settings: Settings | None = None, model: str | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self.model = model or self.settings.model
        self.name = f"ollama:{self.model}"

    def generate_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict,
        images: Sequence[bytes] = (),
        temperature: float = 0.0,
    ) -> dict:
        message: dict = {"role": "user", "content": user}
        if images:
            message["images"] = [base64.b64encode(b).decode("ascii") for b in images]
        payload = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "keep_alive": self.settings.keep_alive,
            "options": {"temperature": temperature, "num_ctx": self.settings.num_ctx},
            "messages": [{"role": "system", "content": system}, message],
        }
        last_err = ""
        for _ in range(self.settings.retries + 1):
            try:
                r = httpx.post(
                    f"{self.settings.ollama_url}/api/chat",
                    json=payload,
                    timeout=self.settings.timeout_s,
                )
                r.raise_for_status()
                content = r.json()["message"]["content"]
                return _extract_json(content)
            except (httpx.HTTPError, KeyError) as exc:
                raise LLMError(f"Ollama request failed: {exc}") from exc
            except json.JSONDecodeError as exc:
                last_err = f"model returned invalid JSON ({exc})"
        raise LLMError(last_err or "model returned no usable JSON")

    def health(self) -> dict:
        try:
            r = httpx.get(f"{self.settings.ollama_url}/api/tags", timeout=5.0)
            r.raise_for_status()
            names = [m.get("name", "") for m in r.json().get("models", [])]
        except (httpx.HTTPError, ValueError) as exc:
            return {
                "reachable": False,
                "backend": "ollama",
                "model": self.model,
                "model_present": False,
                "error": str(exc),
            }
        present = any(n == self.model or n.split(":")[0] == self.model for n in names)
        return {
            "reachable": True,
            "backend": "ollama",
            "model": self.model,
            "model_present": present,
            "installed": names,
        }
