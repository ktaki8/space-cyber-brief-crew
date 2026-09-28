from crew import stamp_brief_date, strip_code_fence


def test_fence_removed_and_date_stamped():
    raw = "```markdown\n# Daily Threat Brief\n**Date:** 2024-06-10  \nbody\n```"
    out = stamp_brief_date(strip_code_fence(raw), "December 02, 2026")
    assert not out.startswith("```")
    assert "**Date:** December 02, 2026" in out and "2024" not in out


def test_date_added_when_missing():
    out = stamp_brief_date("# Brief\nbody", "December 02, 2026")
    assert out.splitlines()[1].startswith("**Date:** December 02, 2026")
