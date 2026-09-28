from crew import stamp_brief_date, strip_code_fence


def test_fence_removed_and_date_stamped():
    raw = "```markdown\n# Daily Threat Brief\n**Date:** 2024-06-10  \nbody\n```"
    out = stamp_brief_date(strip_code_fence(raw), "December 02, 2026")
    assert not out.startswith("```")
    assert "**Date:** December 02, 2026" in out and "2024" not in out


def test_date_added_when_missing():
    out = stamp_brief_date("# Brief\nbody", "December 02, 2026")
    assert out.splitlines()[1].startswith("**Date:** December 02, 2026")


def test_integrity_note_added_only_when_needed():
    from crew import ensure_integrity_note, quarantined_sources
    q = quarantined_sources("demo/injection")
    assert set(q) == {"forum_post_unverified.md", "ground_station_modem_advisory.md"}
    out = ensure_integrity_note("# Brief\nbody\n", q)
    assert "## Source integrity" in out and "ground_station_modem_advisory.md" in out
    assert ensure_integrity_note("# Brief\nContent was quarantined.\n", q) == "# Brief\nContent was quarantined.\n"
    assert ensure_integrity_note("# Brief\n", {}) == "# Brief\n"
    assert quarantined_sources("sources") == {}


def test_writer_guardrail_rejects_invented_sources_then_flags(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    from crew import build_crew
    task = build_crew(sources_dir="demo/injection").tasks[2]
    bad = SimpleNamespace(raw="# Brief\nSource: hexlink_gs400_default_cred_advisory.txt")
    ok, message = task.guardrail(bad)
    assert not ok and "ground_station_modem_advisory.md" in message
    task.retry_count = task.guardrail_max_retries
    ok, text = task.guardrail(bad)
    assert ok and "Attribution warning" in text
    task.retry_count = 0
    good = SimpleNamespace(raw="# Brief\nSources: forum_post_unverified.md, gnss_interference_notice.md, "
                               "ground_station_modem_advisory.md")
    ok, text = task.guardrail(good)
    assert ok and "Attribution warning" not in text and "## Source integrity" in text
