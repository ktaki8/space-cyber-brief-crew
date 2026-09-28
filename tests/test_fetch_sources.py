import fetch_sources
from signals import clean_html, is_space_relevant, score_signal


def test_space_terms_outweigh_general_terms():
    space, terms = score_signal("Satellite ground station modem", "")
    general, _ = score_signal("Vendor network update", "")
    assert space > general and is_space_relevant(terms)


def test_whole_word_matching():
    _, terms = score_signal("Kubernetes namespace workspace issue", "")
    assert "space" not in terms


def test_clean_html_keeps_paragraphs():
    text = clean_html("<h2>Summary</h2><p>One &amp; two</p><ul><li>Fix</li></ul>", keep_paragraphs=True)
    assert "Summary" in text and "One & two" in text and "\n" in text


def test_writes_provenance_and_refuses_sources(tmp_path, monkeypatch):
    item = {
        "source": "CISA ICS Advisories", "title": "Example GNSS Receiver",
        "summary": "GNSS receiver flaw", "body_html": "<p>GNSS receiver flaw</p>",
        "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01",
        "published": "Mon, 05 Oct 2026", "score": 4, "matched_terms": ["gnss", "vulnerability"],
    }
    monkeypatch.setattr(fetch_sources, "collect_signals", lambda per_feed: ([item], []))
    out = tmp_path / "live"
    assert fetch_sources.main(["--out", str(out)]) == 0
    text = (out / "icsa-26-001-01.md").read_text(encoding="utf-8")
    assert "**URL:** https://www.cisa.gov" in text and "not reviewed by an analyst" in text
    assert fetch_sources.main(["--out", "sources"]) == 2


def test_duplicate_advisories_written_once(tmp_path, monkeypatch):
    item = {
        "source": "CISA ICS Advisories", "title": "Botslab Dashcams", "summary": "x",
        "body_html": "<p>x</p>", "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-267-01",
        "published": "", "score": 5, "matched_terms": ["vulnerability"],
    }
    monkeypatch.setattr(fetch_sources, "collect_signals", lambda per_feed: ([item, dict(item)], []))
    out = tmp_path / "live"
    assert fetch_sources.main(["--out", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["icsa-26-267-01.md"]
