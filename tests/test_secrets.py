from penmunshi.verify import verhoeff
from penmunshi.verify.secrets import redact, scan_text

AKID = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def kinds(text: str) -> list[str]:
    return [h.kind for h in scan_text(text)]


def test_aws_pair_detected_and_never_leaks():
    text = f"aws_access_key_id = {AKID}\naws_secret_access_key = {SECRET}\nregion = ap-south-1"
    assert kinds(text) == ["aws_access_key_id", "aws_secret_access_key"]
    red, _ = redact(text)
    assert AKID not in red and SECRET not in red
    assert "[REDACTED:aws_access_key_id]" in red and "region = ap-south-1" in red


def test_cloud_metadata_json_style_secret():
    text = f'{{"AccessKeyId": "ASIAIOSFODNN7EXAMPLE", "SecretAccessKey": "{SECRET}"}}'
    assert "aws_secret_access_key" in kinds(text)


def test_password_assignment_keeps_the_key_name():
    red, hits = redact("login ok with password=hunter2xyz today")
    assert red == "login ok with password=[REDACTED:password] today"
    assert hits[0].confidence == "medium"


def test_json_and_underscore_key_styles():
    assert kinds('{"password": "s3cr3t-pass"}') == ["password"]
    assert kinds("new_password=Winter2026!") == ["password"]
    assert kinds("client_secret: abcd1234efgh") == ["password"]


def test_placeholders_and_already_redacted_are_ignored():
    for text in ("password=****", "password: <redacted>", "password=[REDACTED:password]", "password=null", "token=true"):
        assert scan_text(text) == [], text


def test_jwt_and_bearer():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIifQ.c2lnbmF0dXJlLWZvci1kZW1v"
    assert kinds(f"token {jwt}") == ["jwt"]
    assert kinds("Authorization: Bearer abcdEFGH1234.5678ijkl") == ["bearer_token"]


def test_private_key_block_masked_whole():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----"
    red, hits = redact(f"found:\n{key}\nend")
    assert [h.kind for h in hits] == ["private_key"] and "MIIEow" not in red


def test_url_credentials_mask_only_the_password():
    red, hits = redact("DATABASE_URL=postgres://app:Pa55w0rdX@db.internal:5432/shop")
    assert "Pa55w0rdX" not in red and "postgres://app:" in red and hits[0].kind == "url_credentials"


def test_email_allowlist():
    assert kinds("contact test.user@example.com") == []
    assert kinds("contact someone@corp-mail.in") == ["email"]


def test_verhoeff_reference_values():
    assert verhoeff.check_digit("236") == "3"
    assert verhoeff.validate("2363") and not verhoeff.validate("2364")


def test_aadhaar_needs_valid_checksum():
    prefix = "23456789012"
    good = prefix + verhoeff.check_digit(prefix)
    bad = prefix + str((int(good[-1]) + 1) % 10)
    assert kinds(f"id {good}") == ["aadhaar"]
    assert scan_text(f"id {bad}") == []
    hit = scan_text(f"id {good[:4]} {good[4:8]} {good[8:]}")[0]
    assert hit.preview == "**** " + good[-4:] and hit.checksum_ok is True


def test_payment_card_needs_luhn():
    assert kinds("card 4111 1111 1111 1111") == ["payment_card"]
    assert kinds("card 4111 1111 1111 1112") == []


def test_pan_entity_letter_rule():
    assert kinds("PAN ABCPE1234F") == ["pan"]
    assert kinds("PAN ABCXE1234F") == []


def test_previews_never_contain_the_full_value():
    text = f"{AKID} password=hunter2xyz someone@corp-mail.in"
    for hit in scan_text(text):
        assert text[hit.start : hit.end] != hit.preview
        assert len(hit.preview) <= 12


def test_overlap_prefers_the_specific_detector():
    hits = scan_text(f"password={AKID}")
    assert [h.kind for h in hits] == ["aws_access_key_id"]
