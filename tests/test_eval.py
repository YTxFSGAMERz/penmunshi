import json

from penmunshi.eval import load_cases, render_eval_markdown, run_eval
from penmunshi.verify import cvss as cvss_mod
from penmunshi.verify.secrets import scan_text


def test_cases_are_coherent():
    cases = load_cases()
    assert len(cases) >= 12 and {c.split for c in cases} == {"dev", "heldout"}
    for c in cases:
        assert cvss_mod.score_vector(c.gold["vector"])[1] == c.gold["severity"], c.id
        text = "\n".join([c.notes, *(e.text for e in c.evidence)])
        found = {text[h.start : h.end] for h in scan_text(text)}
        for secret in c.seeded_secrets:  # every seeded secret must really be detectable
            assert secret in found, (c.id, secret)


def test_fault_injection_run_catches_everything():
    rep = run_eval(load_cases(), backend="fake", split="all")
    assert sum(r.faults_injected for r in rep.results) >= 40
    assert sum(r.faults_caught for r in rep.results) == sum(r.faults_injected for r in rep.results)
    assert sum(r.leaks for r in rep.results) == 0
    assert sum(r.cve_emitted_unsourced for r in rep.results) == 0
    assert all(r.severity_ok and r.vector_ok for r in rep.results)
    assert all(r.status == "needs_review" for r in rep.results)  # every faulted case is flagged


def test_clean_run_is_ready_and_reports_render():
    rep = run_eval(load_cases(), backend="fake", split="all", inject_faults=False)
    assert all(r.status == "ready" and r.faults_injected == 0 for r in rep.results)
    md = render_eval_markdown(rep)
    assert "| Metric | dev | heldout |" in md and "Fake backend" in md


def test_split_filter():
    rep = run_eval(load_cases(), backend="fake", split="heldout")
    assert {r.split for r in rep.results} == {"heldout"}


def test_case_files_are_valid_json_with_required_keys():
    for c in load_cases():
        assert {"vector", "severity", "cwe"} <= set(c.gold)
    json.dumps([c.gold for c in load_cases()])
