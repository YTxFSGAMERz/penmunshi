import base64
import json

import httpx
import pytest

from penmunshi.config import Settings
from penmunshi.llm import LLMError, OllamaLLM
from penmunshi.llm.prompts import DRAFT_SCHEMA
from penmunshi.llm.schema import build_schema
from penmunshi.models import FindingDraft


class Resp:
    def __init__(self, content, status=200):
        self._content, self.status_code = content, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)

    def json(self):
        return {"message": {"content": self._content}}


def llm(retries=1):
    return OllamaLLM(Settings(retries=retries), model="gemma4:e4b")


def test_schema_is_flat_strict_and_keeps_the_title_property():
    assert "title" in DRAFT_SCHEMA["properties"]
    assert "$ref" not in json.dumps(DRAFT_SCHEMA) and "$defs" not in DRAFT_SCHEMA
    assert DRAFT_SCHEMA["required"] == list(DRAFT_SCHEMA["properties"])
    assert DRAFT_SCHEMA["properties"]["cvss"]["properties"]["S"]["enum"] == ["U", "C"]
    assert build_schema(FindingDraft) == DRAFT_SCHEMA


def test_from_llm_is_tolerant_but_ignores_rogue_keys():
    d = FindingDraft.from_llm(
        {"title": "t", "summary": "s", "description": "d", "impact": "i",
         "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
         "cwe_ids": [89, None], "cve_ids": "CVE-2020-11022", "severity": "Low"}
    )
    assert d.cwe_ids == ["89"] and d.cve_ids == ["CVE-2020-11022"] and not hasattr(d, "severity")


def test_ollama_payload_and_json_in_prose(monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen.update(url=url, payload=json)
        return Resp('Sure! {"summary": "ok"}')

    monkeypatch.setattr(httpx, "post", fake_post)
    out = llm().generate_json(system="s", user="u", schema={"type": "object"}, images=[b"\x89PNG"])
    assert out == {"summary": "ok"}
    p = seen["payload"]
    assert seen["url"].endswith("/api/chat") and p["format"] == {"type": "object"} and p["stream"] is False
    assert p["messages"][1]["images"] == [base64.b64encode(b"\x89PNG").decode()]
    assert p["options"]["temperature"] == 0.0


def test_invalid_json_retries_then_raises(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(1) or Resp("not json at all"))
    with pytest.raises(LLMError):
        llm(retries=1).generate_json(system="s", user="u", schema={})
    assert len(calls) == 2


def test_http_errors_become_llm_errors(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", boom)
    with pytest.raises(LLMError):
        llm().generate_json(system="s", user="u", schema={})


def test_health_reports_missing_model(monkeypatch):
    class Tags:
        def raise_for_status(self): ...
        def json(self):
            return {"models": [{"name": "llama3:8b"}]}

    monkeypatch.setattr(httpx, "get", lambda *a, **k: Tags())
    h = llm().health()
    assert h["reachable"] and not h["model_present"]
