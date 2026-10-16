import copy

from penmunshi.llm import FakeLLM, LLMError
from penmunshi.pipeline import EvidenceFile, FindingInput, analyze_finding

DRAFT = {
    "title": "SQL injection in login form",
    "affected_asset": "https://shop.acme.test/login",
    "summary": "The login form is injectable.",
    "description": "The username parameter is concatenated into an SQL query.",
    "steps_to_reproduce": ["Open /login", "Send the payload in username"],
    "impact": "An attacker can sign in as any user and read customer data.",
    "remediation": ["Use parameterised queries."],
    "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "cvss_rationale": "Network, no auth, full impact.",
    "cwe_ids": ["89"],
    "cve_ids": [],
    "claims": [{"text": "Login bypass", "evidence_ref": "notes", "quote": "logs in as admin"}],
    "confidence": "confirmed",
}
NOTES = "Payload ' OR 1=1 -- logs in as admin.\nTested on staging."


def run(draft=None, notes=NOTES, **kw):
    d = copy.deepcopy(DRAFT)
    d.update(draft or {})
    llm = FakeLLM(handler=lambda call: d)
    return analyze_finding(FindingInput(id="F-1", notes=notes, **kw), llm), llm


def test_happy_path_is_ready():
    f, _ = run()
    assert f.status == "ready" and f.severity == "Critical" and f.cvss_score == 9.8
    assert f.cwe[0].id == "CWE-89" and f.claims[0].supported


def test_severity_is_owned_by_code_not_the_model():
    f, _ = run({"severity": "Low", "cvss_score": 1.0})
    assert f.severity == "Critical" and f.cvss_score == 9.8 and f.severity_source == "model_metrics"


def test_tester_vector_beats_model_metrics():
    notes = NOTES + "\nMy rating: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    f, _ = run(notes=notes)
    assert f.severity == "Medium" and f.cvss_score == 6.5 and f.severity_source == "tester"


def test_invalid_model_metrics_leave_the_finding_unrated():
    f, _ = run({"cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}})
    assert f.severity == "Critical"  # sanity: valid metrics still work


def test_hallucinated_cve_is_removed_and_reported():
    f, _ = run({"cve_ids": ["CVE-2021-44228"]})
    assert f.cve == [] and f.removed_ids[0].id == "CVE-2021-44228"
    assert any(i.code == "ids_removed" for i in f.lint)


def test_sourced_cve_survives():
    f, _ = run({"cve_ids": ["CVE-2020-11022"]}, notes=NOTES + "\nretire.js: CVE-2020-11022")
    assert [c.id for c in f.cve] == ["CVE-2020-11022"]


def test_unsupported_claim_sends_the_finding_to_review():
    f, _ = run({"claims": [{"text": "Dumped passwords", "evidence_ref": "notes", "quote": "dumped every password hash from the server"}]})
    assert f.status == "needs_review" and not f.claims[0].supported
    assert any(i.code == "unsupported_claims" for i in f.lint)


def test_raw_secrets_never_reach_the_model_prompts():
    notes = "Login worked with password=Sup3rS3cretPw and key AKIAIOSFODNN7EXAMPLE\nlogs in as admin"
    f, llm = run(notes=notes)
    for call in llm.calls:
        assert "Sup3rS3cretPw" not in call["user"] and "AKIAIOSFODNN7EXAMPLE" not in call["user"]
    assert "[REDACTED:password]" in llm.calls[-1]["user"]
    assert {s.kind for s in f.secrets} == {"password", "aws_access_key_id"}


def test_bare_password_repeated_by_the_model_is_still_masked():
    """Regression: found by the first eval run. No regex can spot 'hunter2xyz' without a label,
    but we saw the value in the input, so we mask it in the output by exact match."""
    notes = "Login worked with password=hunter2xyz\nlogs in as admin"
    f, _ = run({"description": "The admin account uses hunter2xyz as its password."}, notes=notes)
    assert "hunter2xyz" not in f.model_dump_json()
    assert "[REDACTED:password]" in f.description
    assert any(i.code == "secret_in_output" and i.level == "error" for i in f.lint)
    assert f.status == "needs_review"


def test_invalid_json_twice_gives_a_failed_draft_not_a_crash():
    llm = FakeLLM(responses=[{"nope": 1}, {"nope": 2}])
    f = analyze_finding(FindingInput(id="F-9", notes=NOTES), llm)
    assert f.status == "needs_review" and f.lint[0].code == "draft_failed"
    assert len(llm.calls) == 2


def test_one_bad_reply_is_retried_with_the_error_in_the_prompt():
    llm = FakeLLM(responses=[{"nope": 1}, copy.deepcopy(DRAFT)])
    f = analyze_finding(FindingInput(id="F-1", notes=NOTES), llm)
    assert f.severity == "Critical" and len(llm.calls) == 2
    assert "rejected" in llm.calls[1]["user"]


def test_vision_pass_feeds_redacted_transcripts_into_the_draft(png_bytes):
    def handler(call):
        if "transcript" in call["schema"]["properties"]:
            return {"transcript": "Authorization: Bearer abcdEFGH1234.5678ijkl\nHTTP/1.1 200 OK", "unreadable_parts": 1}
        return copy.deepcopy(DRAFT)

    llm = FakeLLM(handler=handler)
    f = analyze_finding(FindingInput(id="F-1", notes=NOTES, images=[EvidenceFile("burp.png", png_bytes)]), llm)
    assert llm.calls[0]["n_images"] == 1
    assert "abcdEFGH1234" not in llm.calls[1]["user"] and "EVIDENCE [burp.png]" in llm.calls[1]["user"]
    assert f.evidence[0].kind == "screenshot" and f.evidence[0].secrets == 1
    assert any(i.code == "unreadable_evidence" for i in f.lint)


def test_vision_failure_is_not_fatal(png_bytes):
    def handler(call):
        if "transcript" in call["schema"]["properties"]:
            raise LLMError("model busy")
        return copy.deepcopy(DRAFT)

    f = analyze_finding(FindingInput(id="F-1", notes=NOTES, images=[EvidenceFile("a.png", png_bytes)]), FakeLLM(handler=handler))
    assert f.severity == "Critical" and any(i.code == "vision_failed" for i in f.lint)
