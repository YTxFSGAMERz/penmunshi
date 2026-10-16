from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable


class LLMError(RuntimeError):
    """Raised when the model backend fails or returns unusable output."""


@runtime_checkable
class LLM(Protocol):
    name: str

    def generate_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict,
        images: Sequence[bytes] = (),
        temperature: float = 0.0,
    ) -> dict:
        """Return one JSON object that matches `schema`. Raise LLMError on failure."""
        ...

    def health(self) -> dict: ...
