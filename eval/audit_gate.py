"""Precision and recall of the keyword gate on the labeled stress set.

No model is involved, so this audit reproduces exactly on any machine.
Three gate settings are compared:
  space_term   is_space_relevant(), as used by fetch_sources.py --space-only
  score>=2     the threshold stated in the paper
  score>=1     fetch_sources.py default, with no space term required
"""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))

import signals  # noqa: E402
from stats import clopper_pearson  # noqa: E402

GATES = {
    "space_term": lambda s, m: signals.is_space_relevant(m),
    "score>=2": lambda s, m: s >= 2,
    "score>=1": lambda s, m: s >= 1,
}


def load():
    with open(os.path.join(ROOT, "eval", "gate", "labeled_items.csv"), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def metrics(rows, gate):
    tp = fp = fn = tn = 0
    for r in rows:
        score, matched = signals.score_signal(r["title"], r["summary"])
        hit, truth = GATES[gate](score, matched), r["relevant"] == "1"
        tp += hit and truth
        fp += hit and not truth
        fn += (not hit) and truth
        tn += (not hit) and not truth
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def line(m):
    pos, called = m["tp"] + m["fn"], m["tp"] + m["fp"]
    rec = clopper_pearson(m["tp"], pos) if pos else (0, 0)
    pre = clopper_pearson(m["tp"], called) if called else (0, 0)
    return (f"recall {m['tp']}/{pos} ({m['tp'] / pos:.0%}, exact {rec[0]:.0%}-{rec[1]:.0%}); "
            f"precision {m['tp']}/{called} ({(m['tp'] / called if called else 0):.0%}, exact {pre[0]:.0%}-{pre[1]:.0%})")


def main():
    rows = load()
    result = {}
    for split in ("all", "dev", "heldout"):
        part = rows if split == "all" else [r for r in rows if r["split"] == split]
        print(f"\n{split}: {len(part)} items")
        for gate in GATES:
            m = metrics(part, gate)
            result[f"{split}/{gate}"] = m
            print(f"  {gate:<11} {line(m)}")
    print("\nRecall by group, space_term gate (relevant groups); false alarms for the others:")
    for group in dict.fromkeys(r["group"] for r in rows):
        part = [r for r in rows if r["group"] == group]
        m = metrics(part, "space_term")
        if part[0]["relevant"] == "1":
            print(f"  {group:<13} caught {m['tp']}/{len(part)}")
        else:
            print(f"  {group:<13} false alarms {m['fp']}/{len(part)}")
    short = [r for r in rows if signals.needs_human_triage(r["title"], r["summary"])]
    relevant = sum(r["relevant"] == "1" for r in short)
    print(f"\nRouted to a person as too short to score: {len(short)} item(s), {relevant} of them relevant")
    print("\nMisses and false alarms on the held-out items, space_term gate:")
    for r in rows:
        if r["split"] != "heldout":
            continue
        score, matched = signals.score_signal(r["title"], r["summary"])
        hit = signals.is_space_relevant(matched)
        if hit != (r["relevant"] == "1"):
            print(f"  {r['id']} {'FP' if hit else 'FN'} [{r['group']}/{r['lang']}] {r['title']}")
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
