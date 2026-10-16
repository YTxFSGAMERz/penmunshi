"""JSON-schema helpers. Ollama's structured outputs work best with a flat, fully inlined
schema where every property is required, so we post-process pydantic's output."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


def _walk(node: Any, defs: dict) -> Any:
    if isinstance(node, list):
        return [_walk(x, defs) for x in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        resolved = _walk(defs[node["$ref"].split("/")[-1]], defs)
        extra = {k: _walk(v, defs) for k, v in node.items() if k != "$ref"}
        return {**resolved, **extra}
    out: dict = {}
    for key, value in node.items():
        if key in ("$defs", "title"):
            continue
        if key == "properties":  # property *names* may legitimately be "title"
            out[key] = {name: _walk(sub, defs) for name, sub in value.items()}
        else:
            out[key] = _walk(value, defs)
    if out.get("type") == "object" and "properties" in out:
        out["required"] = list(out["properties"])
        out["additionalProperties"] = False
    return out


def build_schema(model: type[BaseModel]) -> dict:
    raw = model.model_json_schema()
    return _walk(raw, raw.get("$defs", {}))
