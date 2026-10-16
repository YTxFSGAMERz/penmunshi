from pathlib import Path

from penmunshi.llm import FakeLLM
from penmunshi.pipeline import analyze_engagement, load_engagement

DEMO = Path(__file__).resolve().parents[1] / "examples" / "acme-demo"


def test_demo_engagement_loads():
    eng, inputs = load_engagement(DEMO)
    assert eng.client.startswith("ACME") and [i.id for i in inputs][0] == "001-sqli-login"
    assert len(inputs) == 4 and sum(len(i.images) for i in inputs) == 5
    assert inputs[2].tester_vector.startswith("CVSS:3.1/") and inputs[2].tester_severity == "Medium"


def test_demo_runs_end_to_end_with_the_fake_backend():
    report = analyze_engagement(DEMO, FakeLLM())
    assert len(report.findings) == 4 and report.tool["model"] == "fake"
    idor = next(f for f in report.findings if f.id.startswith("003"))
    assert idor.severity == "Medium" and idor.severity_source == "tester"
