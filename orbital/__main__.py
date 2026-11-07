"""python -m orbital check | timeline"""
import argparse
import datetime as dt
import json
import os
import sys

from .claims import CONTRADICTED, verify
from .geometry import TLE_FLOOR_KM, daily_closest, maneuvers
from .tle import Catalog


def cmd_check(args):
    cat = Catalog.from_file(args.tle)
    with open(args.brief, encoding="utf-8") as f:
        claims = verify(f.read(), cat)
    if args.json:
        print(json.dumps([{**c.__dict__, "start": str(c.start), "end": str(c.end),
                           "satellites": [cat.name(s) for s in c.satellites]} for c in claims], indent=2))
    else:
        if not claims:
            print("No orbital claims found.")
        for c in claims:
            sats = " / ".join(cat.name(s) for s in c.satellites)
            print(f"[{c.verdict}] {c.kind}: {sats}, {c.start:%d %b %Y}"
                  + (f" to {c.end:%d %b}" if c.end != c.start else "")
                  + (f", claimed {c.claimed_km:g} km" if c.claimed_km is not None else ""))
            print(f"    \"{c.sentence}\"")
            print(f"    {c.detail}")
    return 1 if any(c.verdict == CONTRADICTED for c in claims) else 0


def cmd_timeline(args):
    cat = Catalog.from_file(args.tle)
    a, b = (cat.resolve(x) for x in (args.a, args.b))
    if a is None or b is None:
        print("Satellite not found in the element sets.")
        return 2
    first = max(cat.coverage(a)[0], cat.coverage(b)[0]).date() + dt.timedelta(days=1)
    last = min(cat.coverage(a)[1], cat.coverage(b)[1]).date()
    if args.start:
        first = dt.date.fromisoformat(args.start)
    if args.end:
        last = dt.date.fromisoformat(args.end)
    rows = daily_closest(cat, a, b, first, last)
    burns = {n: maneuvers(cat, n) for n in (a, b)}
    print(f"Daily closest approach, {cat.name(a)} and {cat.name(b)} (UTC):")
    for day, km, when in rows:
        tag = "  under 2 km" if km < TLE_FLOOR_KM else ""
        print(f"  {day}  {km:10,.1f} km{tag}")
    for n, items in burns.items():
        for t0, t1, net, total in items:
            print(f"Maneuver: {cat.name(n)} {t0:%d %b %H:%M} to {t1:%d %b %H:%M}, "
                  f"altitude change {total:.1f} km (net {net:+.1f} km)")
    if args.plot:
        plot(cat, a, b, rows, burns, args.plot)
        print(f"Wrote {args.plot}")
    return 0


def plot(cat, a, b, rows, burns, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    days = [r[0] for r in rows]
    kms = [max(r[1], TLE_FLOOR_KM) for r in rows]
    fig, ax = plt.subplots(figsize=(10, 4.2))
    ax.plot(days, kms, color="#1f4e79", linewidth=2)
    under = [(d, k) for d, k, r in zip(days, kms, rows) if r[1] < TLE_FLOOR_KM]
    if under:
        ax.scatter([d for d, _ in under], [k for _, k in under], color="#c0392b", zorder=3,
                   label="under ~2 km (closer than TLEs can resolve)")
        ax.legend(loc="lower left", fontsize=8)
    ax.set_yscale("log")
    ax.set_ylabel("Daily closest approach (km, log scale)")
    ax.axhline(TLE_FLOOR_KM, color="#999999", linestyle=":", linewidth=1)
    ax.text(days[-1], TLE_FLOOR_KM * 1.15, "TLE accuracy limit (~2 km)", color="#777777",
            fontsize=8, ha="right")
    for n, items in burns.items():
        for t0, t1, net, total in items:
            if total >= 10:
                ax.axvline(t1.date(), color="#c0392b", alpha=0.5, linewidth=1)
                ax.text(t1.date(), max(kms), f" {cat.name(n)} burn\n {net:+.0f} km", color="#c0392b",
                        fontsize=8, va="top")
    ax.set_title(f"{cat.name(a)} and {cat.name(b)}: daily closest approach from public TLEs")
    ax.grid(True, which="major", alpha=0.3)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path, dpi=150)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m orbital", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="test orbital claims in a brief against element sets")
    c.add_argument("brief")
    c.add_argument("--tle", default=os.getenv("ORBITAL_TLE"), required=os.getenv("ORBITAL_TLE") is None)
    c.add_argument("--json", action="store_true")
    t = sub.add_parser("timeline", help="daily closest approach and maneuvers for two satellites")
    t.add_argument("a")
    t.add_argument("b")
    t.add_argument("--tle", default=os.getenv("ORBITAL_TLE"), required=os.getenv("ORBITAL_TLE") is None)
    t.add_argument("--start")
    t.add_argument("--end")
    t.add_argument("--plot")
    args = p.parse_args(argv)
    return cmd_check(args) if args.cmd == "check" else cmd_timeline(args)


if __name__ == "__main__":
    sys.exit(main())
