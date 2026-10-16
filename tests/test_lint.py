from penmunshi.models import ClaimResult, EvidenceItem, SecretPublic, VerifiedFinding
from penmunshi.verify.lint import lint_finding


def good() -> VerifiedFinding:
    return VerifiedFinding(
        id="F-1",
        title="SQL injection in login form",
        summary="s",
        description="d",
        steps_to_reproduce=["Open /login", "Send the payload"],
        impact="An attacker can log in as any user and read customer data.",
        remediation=["Use parameterised queries everywhere."],
        severity="Critical",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        confidence="confirmed",
        claims=[ClaimResult(text="t", evidence_ref="notes", quote="q" * 10, supported=True, score=1.0, found_in="notes")],
    )


def codes(f, **kw):
    return {i.code: i.level for i in lint_finding(f, **kw)}


def test_clean_finding_has_no_errors():
    assert "error" not in codes(good()).values()


def test_missing_basics_are_errors():
    f = good()
    f.steps_to_reproduce, f.impact, f.remediation = [], "", []
    c = codes(f)
    assert c["no_repro_steps"] == c["no_impact"] == c["no_remediation"] == "error"


def test_severity_mismatch_and_unrated():
    assert codes(good(), tester_severity="Low")["severity_mismatch"] == "warn"
    f = good()
    f.severity = "Unrated"
    assert codes(f)["unrated"] == "error"


def test_unsupported_claims_escalate_when_most_are_bad():
    f = good()
    f.claims += [ClaimResult(text="x", evidence_ref="notes", quote="y" * 10, supported=False, score=0.1)] * 2
    assert codes(f)["unsupported_claims"] == "error"


def test_generic_title_placeholder_and_provisional():
    f = good()
    f.title, f.description, f.confidence = "Bug", "TODO write this", "needs_more_evidence"
    c = codes(f)
    assert c["generic_title"] == "warn" and c["placeholder_text"] == "error" and c["provisional"] == "warn"


def test_evidence_secret_and_unreadable_notes():
    f = good()
    f.evidence = [EvidenceItem(name="a.png", kind="screenshot", transcript="x [unreadable] y", unreadable_parts=1)]
    f.secrets = [SecretPublic(kind="password", preview="ad******", confidence="medium", source="notes")]
    c = codes(f, has_evidence=False, output_redactions=2)
    assert c["no_evidence"] == "warn" and c["unreadable_evidence"] == "warn"
    assert c["secrets_masked"] == "info" and c["secret_in_output"] == "error"


def test_draft_failure_short_circuits():
    assert list(codes(good(), draft_error="bad json")) == ["draft_failed"]


def test_evidence_mismatch_detects_contradicting_status_code():
    f = good()
    f.evidence = [
        EvidenceItem(
            name="resp.png",
            kind="screenshot",
            transcript="HTTP/1.1 200 OK\nContent-Type: text/html",
        )
    ]
    notes = "Observed HTTP 302 redirect to /admin"
    c = codes(f, notes=notes)
    assert c.get("evidence_mismatch") == "warn"


def test_evidence_mismatch_passes_when_evidence_matches_notes():
    f = good()
    f.evidence = [
        EvidenceItem(
            name="resp.png",
            kind="screenshot",
            transcript="HTTP/1.1 302 Found\nLocation: /admin",
        )
    ]
    notes = "Observed HTTP 302 redirect to /admin"
    c = codes(f, notes=notes)
    assert "evidence_mismatch" not in c


def test_evidence_mismatch_detects_port_and_host_discrepancies():
    f = good()
    f.evidence = [
        EvidenceItem(
            name="nmap.txt",
            kind="text",
            transcript="Host: dev.acme.test\nport 8080 open",
        )
    ]
    notes = "Target host: admin.acme.test on port 8443"
    c = codes(f, notes=notes)
    assert c.get("evidence_mismatch") == "warn"

