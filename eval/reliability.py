"""Inter-rater reliability on the locked coding sheets, by field.

    python eval/reliability.py eval/runs/x/coding/coder_a.csv eval/runs/x/coding/coder_b.csv

The 0.85 target is a target. Report the kappa you get, with its interval,
whether or not it clears the target, and adjudicate disagreements afterward.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import cluster_bootstrap, cohen_kappa  # noqa: E402

FIELDS = ["is_claim", "support", "citation_identity", "fabricated", "manipulated", "uncertainty_ok"]


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["claim_id"]: r for r in csv.DictReader(f)}


def main(argv=None):
    argv = argv or sys.argv[1:]
    a, b = load(argv[0]), load(argv[1])
    shared = sorted(set(a) & set(b))
    for field in FIELDS:
        rows = [{"brief": a[c]["brief"], "x": a[c][field].strip().lower(), "y": b[c][field].strip().lower()}
                for c in shared if a[c][field].strip() and b[c][field].strip()]
        if not rows:
            print(f"{field:<20} no paired labels")
            continue
        k = cohen_kappa([r["x"] for r in rows], [r["y"] for r in rows])
        low, high = cluster_bootstrap(rows, "brief", lambda s: cohen_kappa([r["x"] for r in s], [r["y"] for r in s]))
        print(f"{field:<20} n={len(rows):<6} kappa={k:.3f}  95% CI [{low:.3f}, {high:.3f}]  target>0.85: "
              f"{'met' if k > 0.85 else 'not met'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
