"""Unit tests for deterministic retest comparison mode."""

from __future__ import annotations

from pathlib import Path

from penmunshi.models import CweRef, Engagement, Report, VerifiedFinding
from penmunshi.retest import compare_reports, finding_similarity, retest_files


def _make_finding(
    id: str,
    title: str,
    asset: str,
    severity: str,
    score: float,
    cwes: list[str] | None = None,
) -> VerifiedFinding:
    cwe_refs = [CweRef(id=c, name="Weakness", verified=True) for c in (cwes or [])]
    return VerifiedFinding(
        id=id,
        title=title,
        affected_asset=asset,
        summary="Summary of finding",
        description="Description of finding",
        severity=severity,  # type: ignore
        cvss_score=score,
        cwe=cwe_refs,
        status="ready",
    )


def test_finding_similarity():
    f1 = _make_finding("F-01", "SQL Injection in /api/login", "https://api.acme.corp/api/login", "High", 8.2, ["CWE-89"])
    f2 = _make_finding("F-02", "SQLi vulnerability in /api/login", "https://api.acme.corp/api/login", "High", 8.2, ["CWE-89"])
    f3 = _make_finding("F-03", "Missing Content-Security-Policy", "https://acme.corp", "Low", 3.1, ["CWE-693"])

    sim_similar = finding_similarity(f1, f2)
    sim_different = finding_similarity(f1, f3)

    assert sim_similar > 0.70
    assert sim_different < 0.45


def test_compare_reports_categories():
    # Old report: 3 findings
    # 1. SQLi (High, 8.2) -> will be resolved in retest
    # 2. XSS (Medium, 6.1) -> will persist as open
    # 3. IDOR (Low, 3.5) -> will regress to Critical (9.1)
    old_findings = [
        _make_finding("F-01", "SQL Injection in /api/login", "https://api.acme.corp/api/login", "High", 8.2, ["CWE-89"]),
        _make_finding("F-02", "Stored XSS in /comments", "https://acme.corp/comments", "Medium", 6.1, ["CWE-79"]),
        _make_finding("F-03", "IDOR in /users/data", "https://acme.corp/users/data", "Low", 3.5, ["CWE-639"]),
    ]
    old_report = Report(
        engagement=Engagement(project="Acme Assessment Q1"),
        findings=old_findings,
    )

    # New report: 3 findings
    # 1. XSS (Medium, 6.1) -> matches F-02 (open)
    # 2. IDOR (Critical, 9.1) -> matches F-03 (regressed!)
    # 3. RCE (Critical, 9.8) -> new finding!
    new_findings = [
        _make_finding("F-01", "Stored Cross-Site Scripting in /comments", "https://acme.corp/comments", "Medium", 6.1, ["CWE-79"]),
        _make_finding("F-02", "Insecure Direct Object Reference in /users/data", "https://acme.corp/users/data", "Critical", 9.1, ["CWE-639"]),
        _make_finding("F-03", "Remote Code Execution in /upload", "https://acme.corp/upload", "Critical", 9.8, ["CWE-94"]),
    ]
    new_report = Report(
        engagement=Engagement(project="Acme Retest Q2"),
        findings=new_findings,
    )

    result = compare_reports(old_report, new_report)

    assert result.counts == {
        "resolved": 1,
        "open": 1,
        "regressed": 1,
        "new": 1,
    }

    # Verify resolved item
    resolved = result.resolved
    assert len(resolved) == 1
    assert resolved[0].old_id == "F-01"
    assert "SQL Injection" in resolved[0].title

    # Verify open item
    open_items = result.open
    assert len(open_items) == 1
    assert "Cross-Site Scripting" in open_items[0].title
    assert open_items[0].old_id == "F-02"

    # Verify regressed item
    regressed = result.regressed
    assert len(regressed) == 1
    assert "IDOR" in regressed[0].title or "Insecure Direct Object Reference" in regressed[0].title
    assert regressed[0].old_severity == "Low"
    assert regressed[0].new_severity == "Critical"

    # Verify new item
    new_items = result.new
    assert len(new_items) == 1
    assert "Remote Code Execution" in new_items[0].title


def test_retest_files_end_to_end(tmp_path: Path):
    old_f = [_make_finding("F-01", "Missing CSP", "example.com", "Low", 3.1)]
    new_f = []

    old_rep = Report(engagement=Engagement(project="Assessment 1"), findings=old_f)
    new_rep = Report(engagement=Engagement(project="Retest 1"), findings=new_f)

    p1 = tmp_path / "old.json"
    p2 = tmp_path / "new.json"
    p1.write_text(old_rep.model_dump_json(indent=2), encoding="utf-8")
    p2.write_text(new_rep.model_dump_json(indent=2), encoding="utf-8")

    res = retest_files(p1, p2)
    assert res.counts["resolved"] == 1
    assert res.counts["open"] == 0

    md = res.render_markdown()
    assert "Retest Comparison" in md
    assert "RESOLVED" in md

    tbl = res.render_table()
    assert "RESOLVED" in tbl
    assert "Summary: 1 resolved" in tbl
