"""Orbital fact-check, tested on synthetic element sets (no real tracking data)."""
import datetime as dt
import math

import pytest

pytest.importorskip("sgp4")

from sgp4.api import WGS72, Satrec  # noqa: E402
from sgp4.exporter import export_tle  # noqa: E402

import orbital  # noqa: E402
from orbital.claims import CONTRADICTED, SUPPORTED, UNVERIFIABLE, append_report, verify  # noqa: E402
from orbital.geometry import closest_approach, maneuvers  # noqa: E402

EPOCH0 = dt.datetime(2026, 10, 1)


def tle(norad, when, rev_per_day, mean_anomaly_deg):
    sat = Satrec()
    sat.sgp4init(WGS72, "i", norad, (when - dt.datetime(1949, 12, 31)).total_seconds() / 86400,
                 0.0, 0.0, 0.0, 0.0005, math.radians(90), math.radians(97.8),
                 math.radians(mean_anomaly_deg), rev_per_day * 2 * math.pi / 1440, math.radians(10))
    return export_tle(sat)


def catalog():
    """TESTSAT LEAD trails TESTSAT CHASE by ~1 km in the same orbit.
    FARSAT sits on the other side of the orbit. CHASE raises its orbit on 5 October."""
    lines = []
    for day in range(0, 10):
        when = EPOCH0 + dt.timedelta(days=day)
        chase_rev = 15.07 if day < 4 else 14.95  # lower mean motion = higher orbit
        for name, norad, rev, ma in (("TESTSAT LEAD", 90001, 15.07, 10.0),
                                     ("TESTSAT CHASE", 90002, chase_rev, 10.01),
                                     ("FARSAT 7", 90003, 15.07, 190.0)):
            l1, l2 = tle(norad, when, rev, ma)
            lines += [f"0 {name}", l1, l2]
    return orbital.Catalog.from_text("\n".join(lines))


@pytest.fixture(scope="module")
def cat():
    return catalog()


def test_catalog_resolves_names_and_numbers(cat):
    assert cat.resolve("TESTSAT LEAD") == 90001
    assert cat.resolve("Testsat-Chase") == 90002
    assert cat.resolve("90003") == 90003
    assert cat.resolve("Nonexistent 1") is None


def test_close_pair_is_close_and_far_pair_is_far(cat):
    start = EPOCH0 + dt.timedelta(days=1)
    near, _ = closest_approach(cat, 90001, 90002, start, start + dt.timedelta(hours=6))
    far, _ = closest_approach(cat, 90001, 90003, start, start + dt.timedelta(hours=6))
    assert near < 5
    assert far > 5000


def test_maneuver_is_detected_on_the_right_day(cat):
    burns = maneuvers(cat, 90002)
    assert len(burns) == 1
    before, after, net, _ = burns[0]
    assert after.date() == dt.date(2026, 10, 5)
    assert net > 2
    assert maneuvers(cat, 90001) == []


def test_verdicts(cat):
    text = (
        "TESTSAT CHASE passed within 5 km of TESTSAT LEAD on 2 October 2026.\n"
        "FARSAT 7 approached to within 1 km of TESTSAT LEAD on October 2, 2026.\n"
        "TESTSAT CHASE raised its orbit on 5 October 2026.\n"
        "TESTSAT LEAD maneuvered on 3 October 2026.\n"
        "TESTSAT LEAD did not maneuver on 6 October 2026.\n"
        "TESTSAT CHASE came within 10 km of TESTSAT LEAD on 3 March 2026.\n"
    )
    got = [(c.kind, c.verdict) for c in verify(text, cat)]
    assert got == [
        ("proximity", SUPPORTED),
        ("proximity", CONTRADICTED),
        ("maneuver", SUPPORTED),
        ("maneuver", CONTRADICTED),
        ("proximity", UNVERIFIABLE),
    ]


def test_date_ranges_and_metres(cat):
    claims = verify("Between October 2-3, TESTSAT CHASE came within 4000 m of TESTSAT LEAD.", cat)
    assert claims[0].start == dt.date(2026, 10, 2) and claims[0].end == dt.date(2026, 10, 3)
    assert claims[0].claimed_km == 4.0
    assert claims[0].verdict == SUPPORTED


def test_report_is_appended_once_and_not_reread(cat):
    text = "FARSAT 7 approached to within 1 km of TESTSAT LEAD on 2 October 2026."
    once = append_report(text, cat)
    twice = append_report(once, cat)
    assert twice.count(orbital.claims.SECTION_HEADING) == 1
    assert len(verify(twice, cat)) == 1


def test_checker_fails_contradicted_orbital_claim(cat):
    from check_brief import check
    brief = ("UNCLASSIFIED // FOR EDUCATIONAL USE\n**Date:** x\nSource: a.md\n"
             "FARSAT 7 approached to within 1 km of TESTSAT LEAD on 2 October 2026.\n")
    results = {(r["check"], r["level"]) for r in check(brief, {"a.md": "x"}, tle_catalog=cat).results}
    assert ("orbital", "FAIL") in results


def test_redteam_has_an_orbital_goal():
    from redteam.attacks import GOALS
    goal = next(g for g in GOALS if g.key == "orbital")
    assert "Kosmos 2612" in goal.prose
