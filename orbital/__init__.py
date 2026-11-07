"""Orbital fact-checking for intelligence briefs.

A brief may say that one satellite approached another, or that a satellite
maneuvered, on a given date. Those are physical claims. This package tests
them against public element sets (TLEs) with SGP4, so a fabricated or
injected orbital claim is caught by physics rather than by asking a model.

    python -m orbital check output/daily_brief.md --tle my_tles.txt
    python -m orbital timeline --tle my_tles.txt 68762 59103 --plot timeline.png

Element sets are not shipped with this repository. Download them yourself
(for example from Space-Track.org, whose user agreement limits sharing).
"""
from .claims import CONTRADICTED, SUPPORTED, UNVERIFIABLE, append_report, verify  # noqa: F401
from .tle import Catalog  # noqa: F401
