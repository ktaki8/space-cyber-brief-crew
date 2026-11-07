"""Load element sets (3LE text from Space-Track or CelesTrak) and propagate them."""
import bisect
import datetime as dt
import re

from sgp4.api import Satrec, jday

EARTH_RADIUS_KM = 6378.137
MU = 398600.4418  # km^3/s^2


def _epoch(sat):
    jd = sat.jdsatepoch + sat.jdsatepochF
    return dt.datetime(2000, 1, 1, 12) + dt.timedelta(days=jd - 2451545.0)


def _norm(name):
    return re.sub(r"[^a-z0-9]", "", name.lower().replace("kosmos", "cosmos"))


class Catalog:
    """Element sets per NORAD number, sorted by epoch, with name lookup."""

    def __init__(self):
        self.sets = {}     # norad -> [(epoch, Satrec)]
        self.names = {}    # norad -> name from the 0-line
        self._epochs = {}

    @classmethod
    def from_text(cls, text):
        cat = cls()
        lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        name = None
        i = 0
        while i < len(lines):
            ln = lines[i]
            if ln.startswith("1 ") and i + 1 < len(lines) and lines[i + 1].startswith("2 "):
                sat = Satrec.twoline2rv(ln, lines[i + 1])
                cat.sets.setdefault(sat.satnum, []).append((_epoch(sat), sat))
                if name:
                    cat.names[sat.satnum] = name
                name = None
                i += 2
                continue
            name = ln[2:].strip() if ln.startswith("0 ") else ln.strip()
            i += 1
        for norad, items in cat.sets.items():
            items.sort(key=lambda x: x[0])
            cat._epochs[norad] = [e for e, _ in items]
        return cat

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls.from_text(f.read())

    def resolve(self, text):
        """NORAD number for a name or number written in prose, else None."""
        digits = re.sub(r"\D", "", text)
        if digits and int(digits) in self.sets and len(digits) >= 5:
            return int(digits)
        key = _norm(text)
        for norad, name in self.names.items():
            if key and key == _norm(name):
                return norad
        return None

    def name(self, norad):
        return self.names.get(norad, str(norad))

    def coverage(self, norad):
        epochs = self._epochs[norad]
        return epochs[0], epochs[-1]

    def element_set(self, norad, t):
        """The latest element set at or before t (the first one before coverage)."""
        epochs = self._epochs[norad]
        i = bisect.bisect_right(epochs, t) - 1
        return self.sets[norad][max(i, 0)]

    def position(self, norad, t):
        _, sat = self.element_set(norad, t)
        jd, fr = jday(t.year, t.month, t.day, t.hour, t.minute, t.second + t.microsecond / 1e6)
        err, r, _ = sat.sgp4(jd, fr)
        if err:
            raise ValueError(f"SGP4 error {err} for {norad} at {t}")
        return r

    def mean_altitude(self, norad):
        """(epoch, mean altitude in km) for every element set."""
        out = []
        for epoch, sat in self.sets[norad]:
            n = sat.no_kozai / 60.0  # rad/s
            a = (MU / n ** 2) ** (1 / 3)
            out.append((epoch, a - EARTH_RADIUS_KM))
        return out
