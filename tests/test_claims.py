from penmunshi.models import ClaimDraft
from penmunshi.verify.claims import check_claims, match_score

SRC = {
    "notes": "Payload ' OR '1'='1' -- - in username logs in as admin.\nThe server returns a MySQL error.",
    "burp.png": "HTTP/1.1 302 Found\nLocation: /admin/dashboard",
}


def claim(text, ref, quote):
    return ClaimDraft(text=text, evidence_ref=ref, quote=quote)


def test_exact_and_whitespace_case_insensitive_match():
    assert match_score("logs in as admin", SRC["notes"]) == 1.0
    assert match_score("LOGS   IN as ADMIN", SRC["notes"]) == 1.0


def test_near_match_scores_high_and_fabrication_scores_low():
    assert match_score("The server return a MySQL eror", SRC["notes"]) >= 0.85
    assert match_score("the server dumped the complete admin password list", SRC["notes"]) < 0.6


def test_supported_unsupported_and_wrong_source_is_corrected():
    res = check_claims(
        [
            claim("Login bypass", "notes", "logs in as admin"),
            claim("Fabricated", "notes", "the server dumped the complete admin password list"),
            claim("Redirect", "notes", "Location: /admin/dashboard"),  # quote lives in burp.png
        ],
        SRC,
    )
    assert [r.supported for r in res] == [True, False, True]
    assert res[2].found_in == "burp.png"


def test_ref_resolution_is_forgiving():
    res = check_claims([claim("Redirect", "BURP.PNG", "Location: /admin/dashboard")], SRC)
    assert res[0].supported and res[0].evidence_ref == "burp.png"


def test_tiny_quotes_never_count_as_evidence():
    res = check_claims([claim("Vague", "notes", "as")], SRC)
    assert res[0].supported is False
