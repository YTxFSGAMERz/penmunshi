"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "gemma4:e4b"
    timeout_s: float = 300.0
    num_ctx: int = 8192
    max_image_side: int = 1600
    retries: int = 1
    keep_alive: str = "10m"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            ollama_url=os.environ.get("PENMUNSHI_OLLAMA_URL", cls.ollama_url).rstrip("/"),
            model=os.environ.get("PENMUNSHI_MODEL", cls.model),
            timeout_s=_float("PENMUNSHI_TIMEOUT", cls.timeout_s),
            num_ctx=_int("PENMUNSHI_NUM_CTX", cls.num_ctx),
            max_image_side=_int("PENMUNSHI_MAX_IMAGE_SIDE", cls.max_image_side),
            retries=_int("PENMUNSHI_RETRIES", cls.retries),
            keep_alive=os.environ.get("PENMUNSHI_KEEP_ALIVE", cls.keep_alive),
        )
