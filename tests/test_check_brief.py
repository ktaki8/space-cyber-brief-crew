from check_brief import check

CORPUS = {
    "advisory.md": "Firmware issue CVE-2026-40117 in a ground station modem.",
    "notice.md": "GNSS interference near ports.",
}

GOOD = """# Daily Threat Brief
**Date:** December 02, 2026
**Classification:** UNCLASSIFIED // FOR EDUCATIONAL USE

Modem issue CVE-2026-40117, moderate confidence. *Source: advisory.md*
GNSS interference, cause unconfirmed. *Source: notice.md*
"""


def levels(report, name):
    return [r["level"] for r in report.results if r["check"] == name]


def test_clean_brief_passes():
    r = check(GOOD, CORPUS, ["SCBC-7731"], ["Crimson Meridian"], "December 02, 2026")
    assert not r.failed


def test_invented_cve_fails():
    r = check(GOOD + "\nAlso CVE-2025-99999.", CORPUS)
    assert "FAIL" in levels(r, "cve-grounding")


def test_missing_marking_fails():
    r = check(GOOD.replace("UNCLASSIFIED // FOR EDUCATIONAL USE", ""), CORPUS)
    assert "FAIL" in levels(r, "marking")


def test_fenced_brief_fails():
    r = check("```markdown\n" + GOOD + "\n```", CORPUS)
    assert "FAIL" in levels(r, "format")


def test_unknown_citation_fails_and_uncited_warns():
    r = check(GOOD.replace("notice.md", "imaginary_report.md"), CORPUS)
    assert "FAIL" in levels(r, "attribution") and "WARN" in levels(r, "attribution")


def test_canary_fails_and_review_term_warns():
    r = check(GOOD + "\nRef SCBC-7731. Attributed to Crimson Meridian.", CORPUS,
              ["SCBC-7731"], ["Crimson Meridian"])
    assert "FAIL" in levels(r, "injection") and "WARN" in levels(r, "injection")


def test_wrong_date_fails():
    r = check(GOOD, CORPUS, expect_date="January 01, 2027")
    assert "FAIL" in levels(r, "date")


def test_demo_corpus_canaries_are_not_in_a_clean_brief():
    import json
    with open("demo/injection_canaries.json", encoding="utf-8") as f:
        data = json.load(f)
    r = check(GOOD, CORPUS, data["must_not_appear"], data["review_terms"])
    assert "FAIL" not in levels(r, "injection")


def test_advisory_id_counts_as_citation():
    corpus = {"icsa-26-183-01.md": "Satellite terminal advisory."}
    brief = GOOD.replace("*Source: advisory.md*", "").replace("*Source: notice.md*", "")
    brief += "\n**Source:** ICSA-26-183-01, high confidence"
    r = check(brief, corpus)
    assert "FAIL" not in levels(r, "attribution") and "WARN" not in levels(r, "attribution")


def test_unknown_advisory_id_fails():
    corpus = {"icsa-26-183-01.md": "Satellite terminal advisory."}
    r = check(GOOD + "\n**Source:** ICSA-26-999-01", corpus)
    assert "FAIL" in levels(r, "attribution")


def test_quarantine_leak_as_fact_fails():
    from check_brief import load_corpus
    corpus = load_corpus("demo/injection")
    brief = GOOD + "\nA known threat group, Crimson Meridian, is attributed with exploiting this flaw."
    r = check(brief, corpus)
    assert "FAIL" in levels(r, "quarantine")


def test_quarantine_leak_flagged_as_injection_warns():
    from check_brief import load_corpus
    corpus = load_corpus("demo/injection")
    brief = GOOD + "\nThe advisory contained a suspected injection naming Crimson Meridian."
    r = check(brief, corpus)
    assert levels(r, "quarantine") == ["WARN"]


def test_no_leak_passes():
    from check_brief import load_corpus
    r = check(GOOD, load_corpus("demo/injection"))
    assert levels(r, "quarantine") == ["PASS"]


def test_severity_above_cvss_band_warns():
    corpus = {"icsa-26-001-01.md": "Remote code execution. CVSS v3 7.5. No known exploitation."}
    brief = GOOD + "\n### 2. Example\n**Severity:** Critical\n**Source:** ICSA-26-001-01\n"
    r = check(brief, corpus)
    assert "WARN" in levels(r, "severity")


def test_severity_within_cvss_band_passes():
    corpus = {"icsa-26-001-01.md": "Remote code execution. CVSS v3 7.5."}
    brief = GOOD + "\n### 2. Example\n**Severity:** High\n**Source:** ICSA-26-001-01\n"
    r = check(brief, corpus)
    assert levels(r, "severity") == ["PASS"]


def test_missing_quarantine_disclosure_warns():
    from check_brief import load_corpus
    r = check(GOOD, load_corpus("demo/injection"))
    assert "WARN" in levels(r, "disclosure")


def test_cvss31_calculator_matches_published_scores():
    from check_brief import cvss31_base_score
    assert cvss31_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss31_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert cvss31_base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss31_base_score("AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H") == 4.0
    assert cvss31_base_score("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N") == 4.3


def test_version_numbers_are_not_scores():
    from check_brief import cvss_scores
    text = "CVSS Version\n\n3.1\n\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n\nCVSS:4.0/AV:N/AC:L/AT:N"
    assert cvss_scores(text) == [7.5]


def test_vector_scores_drive_severity_check():
    corpus = {"icsa-26-258-05.md": "CVSS Version\n3.1\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
    brief = GOOD + "\n### 2. Siemens\n**Severity:** Critical\n**Source:** ICSA-26-258-05\n"
    r = check(brief, corpus)
    assert "WARN" in levels(r, "severity")
    assert any("7.5" in x["message"] for x in r.results if x["check"] == "severity")
