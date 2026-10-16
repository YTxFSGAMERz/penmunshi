import pytest

from penmunshi.verify import cvss as c

OK = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")


def test_known_vectors():
    assert c.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "Critical")
    assert c.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == (6.1, "Medium")
    assert c.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") == (5.3, "Medium")


def test_no_impact_is_none_severity():
    assert c.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == (0.0, "None")


def test_build_vector_validates_every_metric():
    assert c.build_vector(OK) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert c.build_vector({**OK, "AV": "X"}) is None
    assert c.build_vector({**OK, "AV": "NN"}) is None
    assert c.build_vector({k: v for k, v in OK.items() if k != "A"}) is None


def test_garbage_vector_returns_none():
    assert c.score_vector("CVSS:3.1/AV:X") is None
    assert c.score_vector("") is None
    assert c.score_vector(None) is None


@pytest.mark.parametrize(
    ("score", "band"),
    [(0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"), (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical")],
)
def test_severity_bands(score, band):
    assert c.severity_from_score(score) == band


def test_find_vector_in_tester_notes():
    text = "Rated by me: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N because of IDOR."
    assert c.find_vector(text) == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    assert c.find_vector("no vector here") is None


def test_normalise_severity_text():
    assert c.normalise_severity("crit") == "Critical"
    assert c.normalise_severity("Informational") == "None"
    assert c.normalise_severity("banana") is None
