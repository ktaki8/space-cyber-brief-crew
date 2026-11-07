"""Find orbital claims in a brief and test them against element sets.

Two kinds of claim are checked:

* proximity: "<A> passed within 5 km of <B> on 16 October 2026"
* maneuver:  "<A> raised its orbit on 30 September"

A claim is SUPPORTED when the computed geometry agrees, CONTRADICTED when it
does not, and UNVERIFIABLE when a satellite is not in the data, the date is
outside the data, or the sentence cannot be parsed. TLE positions are good to
roughly a kilometre or more, so distances under TLE_FLOOR_KM are reported as
"under 2 km", never as an exact figure.
"""
import datetime as dt
import re
from dataclasses import dataclass, field

from .geometry import TLE_FLOOR_KM, closest_approach, maneuvers

SUPPORTED, CONTRADICTED, UNVERIFIABLE = "SUPPORTED", "CONTRADICTED", "UNVERIFIABLE"

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
MONTH = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?"
DASH = r"\s*(?:-|–|—|to|through)\s*"
DATE_PATTERNS = [
    # 2026-10-16
    (re.compile(r"\b(20\d\d)-(\d\d)-(\d\d)\b"), "iso"),
    # October 15-18, 2026 / October 16, 2026 / Oct 16
    (re.compile(MONTH + r"\s+(\d{1,2})(?:" + DASH + r"(\d{1,2}))?(?:st|nd|rd|th)?(?:,?\s+(20\d\d))?", re.I), "mdy"),
    # 15-18 October 2026 / 16 October 2026 / 16 Oct
    (re.compile(r"\b(\d{1,2})(?:" + DASH + r"(\d{1,2}))?(?:st|nd|rd|th)?\s+" + MONTH + r"(?:,?\s+(20\d\d))?", re.I), "dmy"),
]
DISTANCE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(km|kilomet(?:er|re)s?|m|met(?:er|re)s?)\b", re.I)
PROXIMITY_WORDS = re.compile(r"within|approach|closest|passed|came|close to|rendezvous|proximity|distance|separation|neared|closed", re.I)
MANEUVER_WORDS = re.compile(r"maneuver|manoeuvre|burn|raised|lowered|boost|orbit raise|changed (?:its|their) orbit|altitude change", re.I)
NEGATION = re.compile(r"\b(?:no|not|never|without|did not|didn't)\b", re.I)
SENTENCE = re.compile(r"[^.!?\n]+(?:[.!?](?!\d)|$)")


@dataclass
class Claim:
    kind: str
    sentence: str
    satellites: list
    start: dt.date
    end: dt.date
    claimed_km: float = None
    verdict: str = UNVERIFIABLE
    detail: str = ""
    computed: dict = field(default_factory=dict)


def _month(token):
    return MONTHS[token.lower()[:3]]


def find_dates(text, default_year):
    """(start, end) date ranges in text, in order."""
    out = []
    for rx, kind in DATE_PATTERNS:
        for m in rx.finditer(text):
            try:
                if kind == "iso":
                    d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                    out.append((m.start(), d, d))
                elif kind == "mdy":
                    mon, d0, d1, yr = m.group(1), m.group(2), m.group(3), m.group(4)
                    y = int(yr) if yr else default_year
                    out.append((m.start(), dt.date(y, _month(mon), int(d0)),
                                dt.date(y, _month(mon), int(d1 or d0))))
                else:
                    d0, d1, mon, yr = m.group(1), m.group(2), m.group(3), m.group(4)
                    y = int(yr) if yr else default_year
                    out.append((m.start(), dt.date(y, _month(mon), int(d0)),
                                dt.date(y, _month(mon), int(d1 or d0))))
            except ValueError:
                continue
    out.sort(key=lambda x: x[0])
    seen, unique = set(), []
    for pos, a, b in out:
        if not any(abs(pos - p) < 3 for p in seen):
            seen.add(pos)
            unique.append((a, b))
    return unique


def satellite_patterns(cat):
    pats = {}
    for norad, name in cat.names.items():
        tokens = re.findall(r"[a-z]+|\d+", name.lower())
        parts = ["(?:kosmos|cosmos)" if t in ("kosmos", "cosmos") else re.escape(t) for t in tokens]
        pats[norad] = re.compile(r"\b(?:" + r"[\s\-]?".join(parts) + r"|" + str(norad) + r")\b", re.I)
    return pats


def mentioned(sentence, pats):
    hits = [(m.start(), norad) for norad, rx in pats.items() for m in rx.finditer(sentence)]
    out = []
    for _, norad in sorted(hits):
        if norad not in out:
            out.append(norad)
    return out


def _km(m):
    value = float(m.group(1).replace(",", "."))
    return value if m.group(2).lower().startswith("k") else value / 1000.0


def _fmt(km):
    return f"under {TLE_FLOOR_KM:g} km" if km < TLE_FLOOR_KM else f"{km:,.0f} km" if km >= 10 else f"{km:.1f} km"


def _in_coverage(cat, norads, start, end):
    for n in norads:
        first, last = cat.coverage(n)
        if dt.datetime.combine(start, dt.time()) < first - dt.timedelta(days=1) or \
                dt.datetime.combine(end, dt.time()) > last + dt.timedelta(days=1):
            return False
    return True


def check_proximity(cat, claim):
    a, b = claim.satellites[:2]
    if not _in_coverage(cat, (a, b), claim.start, claim.end):
        claim.detail = "Date is outside the element-set data."
        return claim
    t0 = dt.datetime.combine(claim.start, dt.time())
    t1 = dt.datetime.combine(claim.end, dt.time()) + dt.timedelta(days=1, seconds=-1)
    km, when = closest_approach(cat, a, b, t0, t1)
    claim.computed = {"closest_km": round(km, 2), "at_utc": when.isoformat(timespec="minutes")}
    tolerance = max(TLE_FLOOR_KM, 0.2 * claim.claimed_km)
    if km <= claim.claimed_km + tolerance:
        claim.verdict = SUPPORTED
        claim.detail = f"Closest computed approach {_fmt(km)} at {when:%d %b %H:%M} UTC."
    else:
        claim.verdict = CONTRADICTED
        claim.detail = (f"Closest computed approach in that window was {_fmt(km)} "
                        f"({when:%d %b %H:%M} UTC), not {claim.claimed_km:g} km.")
    return claim


def check_maneuver(cat, claim):
    norad = claim.satellites[0]
    if not _in_coverage(cat, (norad,), claim.start, claim.end):
        claim.detail = "Date is outside the element-set data."
        return claim
    lo = dt.datetime.combine(claim.start, dt.time()) - dt.timedelta(days=1)
    hi = dt.datetime.combine(claim.end, dt.time()) + dt.timedelta(days=2)
    found = [m for m in maneuvers(cat, norad) if lo <= m[1] and m[0] <= hi]
    if found:
        before, after, net, total = found[0]
        claim.verdict = SUPPORTED
        claim.computed = {"between_utc": [before.isoformat(timespec="minutes"), after.isoformat(timespec="minutes")],
                          "net_altitude_change_km": round(net, 1), "total_altitude_change_km": round(total, 1)}
        claim.detail = (f"Element sets show an altitude change of {total:.1f} km "
                        f"(net {net:+.1f} km) between {before:%d %b} and {after:%d %b}.")
        return claim
    epochs = [e for e, _ in cat.sets[norad] if lo <= e <= hi]
    if len(epochs) < 2:
        claim.detail = "Too few element sets around that date to tell."
        return claim
    claim.verdict = CONTRADICTED
    claim.detail = f"No altitude change above 2 km in {len(epochs)} element sets around that date."
    return claim


def extract(text, cat, default_year=None):
    text = text.split("\n" + SECTION_HEADING)[0]  # never re-read our own report
    pats = satellite_patterns(cat)
    if default_year is None:
        default_year = max(cat.coverage(n)[1] for n in cat.sets).year
    claims = []
    for sm in SENTENCE.finditer(text):
        sentence = sm.group(0).strip()
        sats = mentioned(sentence, pats)
        if not sats:
            continue
        dates = find_dates(sentence, default_year)
        if not dates:
            continue
        start, end = dates[0]
        dist = DISTANCE.search(sentence)
        if len(sats) >= 2 and dist and PROXIMITY_WORDS.search(sentence):
            claims.append(Claim("proximity", sentence, sats[:2], start, end, claimed_km=_km(dist)))
        elif MANEUVER_WORDS.search(sentence) and not NEGATION.search(sentence):
            claims.append(Claim("maneuver", sentence, sats[:1], start, end))
    return claims


def verify(text, cat, default_year=None):
    out = []
    for claim in extract(text, cat, default_year):
        out.append(check_proximity(cat, claim) if claim.kind == "proximity" else check_maneuver(cat, claim))
    return out


SECTION_HEADING = "## Orbital Check"


def report_section(claims, cat):
    """Markdown appended to a brief by code: each orbital claim and its verdict."""
    if not claims:
        return ""
    rows = ["| Claim | Verdict | What the element sets show |", "|---|---|---|"]
    for c in claims:
        text = c.sentence.replace("|", "/")
        rows.append(f"| {text} | **{c.verdict}** | {c.detail} |")
    return (f"\n\n{SECTION_HEADING}\n\nComputed in code with SGP4 from public element sets, not "
            "written by a model. TLE positions are accurate to roughly a kilometre or more.\n\n"
            + "\n".join(rows) + "\n")


def append_report(text, cat):
    body = text.split("\n" + SECTION_HEADING)[0].rstrip()
    return body + report_section(verify(body, cat), cat)
