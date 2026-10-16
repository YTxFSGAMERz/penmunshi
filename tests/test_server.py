import io

import pytest
from fastapi.testclient import TestClient

from penmunshi.llm import FakeLLM
from penmunshi.server import create_app


@pytest.fixture()
def client():
    return TestClient(create_app(llm=FakeLLM()))


def test_index_and_health(client):
    assert "PenMunshi" in client.get("/").text
    j = client.get("/api/health").json()
    assert j["reachable"] and j["backend"] == "fake" and "version" in j


def test_analyze_masks_secrets_and_returns_a_finding(client):
    r = client.post("/api/analyze", data={"notes": "Login bypass found.\npassword=hunter2xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body["severity"] in {"Medium", "Critical", "High", "Low"} and body["secrets"][0]["kind"] == "password"
    assert "hunter2xyz" not in r.text


def test_analyze_rejects_empty_input(client):
    assert client.post("/api/analyze", data={}).status_code == 422


def test_analyze_accepts_a_screenshot(client, png_bytes):
    r = client.post("/api/analyze", data={"notes": "x marks the spot, really"}, files=[("files", ("shot.png", io.BytesIO(png_bytes), "image/png"))])
    assert r.status_code == 200 and r.json()["evidence"][0]["name"] == "shot.png"


def test_export_formats(client):
    finding = client.post("/api/analyze", data={"notes": "Open redirect on /go?url="}).json()
    body = {"engagement": {"client": "ACME"}, "findings": [finding], "executive_summary": "Short summary."}
    assert "Penetration Test Report" in client.post("/api/export?fmt=html", json=body).text
    assert "## Findings overview" in client.post("/api/export?fmt=md", json=body).text
    docx = client.post("/api/export?fmt=docx", json=body)
    assert docx.content[:2] == b"PK"
    assert client.post("/api/export?fmt=pdf", json=body).status_code == 422


def test_summary_endpoint(client):
    finding = client.post("/api/analyze", data={"notes": "Open redirect on /go?url="}).json()
    j = client.post("/api/summary", json={"findings": [finding]}).json()
    assert "summary" in j
