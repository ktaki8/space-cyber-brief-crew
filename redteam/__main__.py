"""Red-team mode: attack an AI threat-intelligence pipeline and score what gets through.

    python -m redteam audit                          # offline: what survives the sanitizer?
    python -m redteam campaign --out redteam_runs/c1 # generate, run this crew (sanitizer off and on), score
    python -m redteam campaign --out redteam_runs/c2 --cmd "python my_pipeline.py {sources} {output}"

--cmd runs any pipeline that reads a folder of documents and writes one brief:
{sources} is the attacked corpus folder and {output} is where the brief must go.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redteam import campaign  # noqa: E402
from redteam.attacks import GOALS, TECHNIQUES  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m redteam", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="offline: which attacks survive the sanitizer (no model calls)")
    a.add_argument("--out", default=os.path.join("redteam_runs", "audit"))

    c = sub.add_parser("campaign", help="generate attacks, run a target, score it")
    c.add_argument("--out", required=True)
    c.add_argument("--cmd", help="external pipeline command with {sources} and {output}")
    c.add_argument("--arms", nargs="+", default=["off", "on"], choices=["off", "on"],
                   help="for this crew: sanitizer off, on, or both (default both)")
    c.add_argument("--techniques", nargs="+", choices=[t.key for t in TECHNIQUES])
    c.add_argument("--goals", nargs="+", choices=[g.key for g in GOALS])
    c.add_argument("--limit", type=int, help="stop after this many target runs (smoke test)")

    s = sub.add_parser("score", help="re-score an existing campaign")
    s.add_argument("--out", required=True)

    args = p.parse_args(argv)

    if args.command == "audit":
        os.makedirs(args.out, exist_ok=True)
        rows = campaign.audit()
        path = campaign.write_report(args.out, audit_rows=rows, title="Sanitizer audit")
        n = sum(r["survived"] for r in rows)
        print(f"{n} of {len(rows)} attacks survive the sanitizer and reach the model.")
        for t in TECHNIQUES:
            got = [r["goal"] for r in rows if r["technique"] == t.key and r["survived"]]
            print(f"  {t.label:<24} {'reaches model' if got else 'quarantined'}"
                  + (f" ({len(got)}/{len(GOALS)})" if got else ""))
        print(f"Scorecard: {path}")
        return 0

    if args.command == "campaign":
        campaign.generate(args.out, techniques=args.techniques, goals=args.goals)
        arm_dirs = {}
        if args.cmd:
            arm = campaign.run(args.out, target="external", cmd_template=args.cmd, limit=args.limit)
            arm_dirs[arm] = os.path.join(args.out, "briefs", arm)
        else:
            for a in args.arms:
                arm = campaign.run(args.out, sanitize=(a == "on"), limit=args.limit)
                arm_dirs[arm] = os.path.join(campaign.REPO, "output", "redteam",
                                             os.path.basename(os.path.abspath(args.out)), arm)
        results = campaign.score(args.out, arm_dirs)
        path = campaign.write_report(args.out, results=results, audit_rows=campaign.audit(),
                                     title="Red-team scorecard")
        print(f"Scorecard: {path}")
        return 0

    if args.command == "score":
        import json
        base = os.path.join(campaign.REPO, "output", "redteam", os.path.basename(os.path.abspath(args.out)))
        arm_dirs = {}
        for root in (base, os.path.join(args.out, "briefs")):
            if os.path.isdir(root):
                for arm in sorted(os.listdir(root)):
                    arm_dirs[arm] = os.path.join(root, arm)
        results = campaign.score(args.out, arm_dirs)
        print(json.dumps({k: sum(bool(v) for v in c.values() if v is not None) for k, c in results.items()}))
        print(f"Scorecard: {campaign.write_report(args.out, results=results, audit_rows=campaign.audit())}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
