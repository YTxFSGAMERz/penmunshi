from penmunshi.verify.ids import extract_cves, normalise_cve, normalise_cwe, verify_ids


def test_cve_needs_provenance(catalog):
    sources = {"notes": "scanner flagged CVE-2020-11022 on jquery"}
    r = verify_ids(["CVE-2020-11022", "CVE-2021-44228"], [], sources, catalog)
    assert [c.id for c in r.cve] == ["CVE-2020-11022"]
    assert [x.id for x in r.removed] == ["CVE-2021-44228"]
    assert "not written" in r.removed[0].reason


def test_implausible_cve_year_removed(catalog):
    r = verify_ids(["CVE-2099-12345"], [], {"notes": "CVE-2099-12345"}, catalog)
    assert r.cve == [] and r.removed[0].id == "CVE-2099-12345"


def test_known_exploited_flag_comes_from_the_catalog(catalog):
    r = verify_ids(["CVE-2021-44228"], [], {"tool_output": "log4j CVE-2021-44228"}, catalog)
    assert r.cve[0].known_exploited is True


def test_cwe_uses_the_canonical_catalog_name(catalog):
    r = verify_ids([], ["89", "CWE-79"], {"notes": "x"}, catalog)
    assert [c.id for c in r.cwe] == ["CWE-89", "CWE-79"]
    assert "SQL Injection" in r.cwe[0].name and all(c.verified for c in r.cwe)


def test_hallucinated_cwe_is_removed_but_tester_written_one_is_kept(catalog):
    r = verify_ids([], ["99999"], {"notes": "nothing"}, catalog)
    assert r.cwe == [] and r.removed[0].id == "CWE-99999"
    r2 = verify_ids([], ["99999"], {"notes": "I think this is CWE-99999"}, catalog)
    assert r2.cwe[0].verified is False


def test_normalisers_and_dedupe(catalog):
    assert normalise_cwe("CWE-079") == "79" and normalise_cwe("none") is None
    assert normalise_cve("cve 2021 44228") == "CVE-2021-44228"
    assert extract_cves("CVE-2021-44228, cve-2021-44228") == {"CVE-2021-44228"}
    r = verify_ids([], ["89", "CWE-89", "089"], {"notes": ""}, catalog)
    assert len(r.cwe) == 1
