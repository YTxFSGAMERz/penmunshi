"""A deterministic stand-in for the model. Used by tests, CI, `--backend fake` and the eval
fault-injection mode. It never pretends to be Gemma: results are labelled as fake."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence


class FakeLLM:
    name = "fake"

    def __init__(
        self,
        handler: Callable[[dict], dict] | None = None,
        responses: list[dict | Exception] | None = None,
    ) -> None:
        self.handler = handler
        self.responses = list(responses or [])
        self.calls: list[dict] = []

    # -- LLM protocol -----------------------------------------------------------
    def generate_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict,
        images: Sequence[bytes] = (),
        temperature: float = 0.0,
    ) -> dict:
        call = {"system": system, "user": user, "schema": schema, "n_images": len(images)}
        self.calls.append(call)
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if self.handler:
            return self.handler(call)
        return self._default(call)

    def health(self) -> dict:
        return {"reachable": True, "backend": "fake", "model": "fake", "model_present": True}

    # -- defaults -----------------------------------------------------------------
    @staticmethod
    def _default(call: dict) -> dict:
        props = call["schema"].get("properties", {})
        if "transcript" in props:
            return {"transcript": "[fake backend: no model was run]", "unreadable_parts": 0}
        if "title" in props:
            return FakeLLM._default_draft(call["user"])
        if "summary" in props:
            return {
                "summary": "This is a placeholder summary produced by the fake backend. "
                "Run with a real model for a real summary."
            }
        return {}

    @staticmethod
    def _default_draft(user_prompt: str) -> dict:
        m = re.search(r"TESTER NOTES:\n<<<\n(.*?)\n>>>", user_prompt, re.S)
        notes = (m.group(1) if m else "").strip()
        first = next((ln.strip(" #-*\t") for ln in notes.splitlines() if ln.strip()), "Untitled")

        # Prefer tool output as primary evidence source if present
        m_tool = re.search(r"TOOL OUTPUT:\n<<<\n(.*?)\n>>>", user_prompt, re.S)
        tool = (m_tool.group(1) if m_tool else "").strip()
        if tool and tool != "(empty)":
            quote_text = next((ln.strip() for ln in tool.splitlines() if ln.strip()), "")[:80]
            ref = "tool_output"
        else:
            quote_text = first[:120]
            ref = "notes"

        return {
            "title": first[:90] or "Untitled finding",
            "affected_asset": "",
            "summary": f"Fake-backend summary for: {first[:80]}",
            "description": "Placeholder description from the fake backend. " + first,
            "steps_to_reproduce": ["Review the tester notes."],
            "impact": "Impact placeholder from the fake backend: replace by running a real model.",
            "remediation": ["Remediation placeholder from the fake backend."],
            "cvss": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "L", "I": "N", "A": "N",
            },
            "cvss_rationale": "Fake backend default metrics.",
            "cwe_ids": [],
            "cve_ids": [],
            "claims": [{"text": first[:120], "evidence_ref": ref, "quote": quote_text}],
            "confidence": "likely",
        }
