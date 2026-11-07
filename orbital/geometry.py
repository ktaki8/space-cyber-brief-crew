"""Distances and maneuvers computed from element sets."""
import datetime as dt
import math

STEP_SECONDS = 30
TLE_FLOOR_KM = 2.0  # TLE positions are good to roughly a kilometre or more


def distance(cat, a, b, t):
    ra, rb = cat.position(a, t), cat.position(b, t)
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(ra, rb)))


def closest_approach(cat, a, b, start, end, step=STEP_SECONDS):
    """(km, time) of the smallest separation between start and end."""
    best = (float("inf"), None)
    t = start
    while t <= end:
        d = distance(cat, a, b, t)
        if d < best[0]:
            best = (d, t)
        t += dt.timedelta(seconds=step)
    return best


def daily_closest(cat, a, b, first_day, last_day):
    out = []
    day = dt.datetime.combine(first_day, dt.time())
    while day.date() <= last_day:
        km, when = closest_approach(cat, a, b, day, day + dt.timedelta(days=1) - dt.timedelta(seconds=1))
        out.append((day.date(), km, when))
        day += dt.timedelta(days=1)
    return out


def maneuvers(cat, norad, threshold_km=2.0, max_gap_days=3.0):
    """Element-set pairs whose mean altitude jumps by more than drag explains.

    Returns (epoch_before, epoch_after, net_change_km, total_change_km). Gaps longer than
    max_gap_days are skipped because a jump across them cannot be dated.
    """
    series = cat.mean_altitude(norad)
    jumps = []
    for (t0, h0), (t1, h1) in zip(series, series[1:]):
        gap = (t1 - t0).total_seconds() / 86400
        if 0 < gap <= max_gap_days and abs(h1 - h0) > threshold_km:
            jumps.append([t0, t1, h1 - h0, abs(h1 - h0)])
    merged = []  # one burn often spans several element sets
    for j in jumps:
        if merged and (j[0] - merged[-1][1]).total_seconds() <= 86400:
            merged[-1][1] = j[1]
            merged[-1][2] += j[2]
            merged[-1][3] += j[3]
        else:
            merged.append(j)
    return [tuple(m) for m in merged]
