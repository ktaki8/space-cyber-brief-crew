"""Turn scores.csv into results.md.

Every rate shows numerator and denominator. Intervals resample whole bundles,
because 3 documents run 10 times is 3 documents, not 30 reports. With four
bundles those intervals are rough, and the document-by-document table is the
honest view. Between-document and between-run variation are shown separately.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import clopper_pearson, cluster_bootstrap  # noqa: E402

NUM = ["invented_ids", "invented_files", "citations_present", "wrong_reference", "facts_found", "facts_total",
       "critical_found", "critical_total", "abstain_found", "abstain_total", "conflated", "confidence_labels",
       "text_attempts", "tool_calls", "effects", "n_docs"]


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    ok = []
    for r in rows:
        if r["status"] == "ok":
            for k in NUM:
                r[k] = float(r.get(k) or 0)
            ok.append(r)
    return rows, ok


def ratio(rows, top, bottom):
    d = sum(r[bottom] for r in rows)
    return sum(r[top] for r in rows) / d if d else None


def share(rows, test):
    return sum(1 for r in rows if test(r)) / len(rows) if rows else None


METRICS = [
    ("Briefs with an invented ID", lambda r: r["invented_ids"] > 0, None),
    ("Briefs citing an unknown file", lambda r: r["invented_files"] > 0, None),
    ("Briefs with a wrong reference", lambda r: r["wrong_reference"] > 0, None),
    ("Briefs with screened conflation", lambda r: r["conflated"] > 0, None),
]
RATIOS = [("Document citations present", "citations_present", "n_docs"),
          ("Supported-fact recall (screen)", "facts_found", "facts_total"),
          ("Critical-warning recall (screen)", "critical_found", "critical_total"),
          ("Open questions left open (screen)", "abstain_found", "abstain_total")]


def fmt(value):
    return "n/a" if value is None else f"{value:.1%}"


def arm_table(rows):
    arms = sorted({r["arm"] for r in rows})
    lines = ["| Metric | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
    for name, test, _ in METRICS:
        cells = []
        for arm in arms:
            group = [r for r in rows if r["arm"] == arm]
            k = sum(1 for r in group if test(r))
            lo, hi = clopper_pearson(k, len(group))
            cells.append(f"{k}/{len(group)} ({fmt(k / len(group))}; exact {lo:.1%}-{hi:.1%})")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    for name, top, bottom in RATIOS:
        cells = []
        for arm in arms:
            group = [r for r in rows if r["arm"] == arm]
            cells.append(f"{int(sum(r[top] for r in group))}/{int(sum(r[bottom] for r in group))} "
                         f"({fmt(ratio(group, top, bottom))})")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return lines


def by_bundle(rows, top, bottom):
    bundles, arms = sorted({r["bundle"] for r in rows}), sorted({r["arm"] for r in rows})
    lines = ["| Bundle | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
    for b in bundles:
        lines.append(f"| {b} | " + " | ".join(fmt(ratio([r for r in rows if r["arm"] == a and r["bundle"] == b],
                                                        top, bottom)) for a in arms) + " |")
    return lines


def factorial(rows):
    tag = lambda r: (r["arm"].startswith("T1"), "_rules" in r["arm"] and "norules" not in r["arm"])

    def effects(sample):
        cell = {}
        for t in (False, True):
            for u in (False, True):
                group = [r for r in sample if tag(r) == (t, u)]
                cell[(t, u)] = (sum(r["invented_ids"] > 0 for r in group) / len(group)) if group else None
        if any(v is None for v in cell.values()):
            return None
        return cell

    point = effects(rows)
    if not point:
        return ["Not all four cells are present."]
    calc = {
        "Tools main effect": lambda c: (c[(True, False)] + c[(True, True)] - c[(False, False)] - c[(False, True)]) / 2,
        "Rules main effect": lambda c: (c[(False, True)] + c[(True, True)] - c[(False, False)] - c[(True, False)]) / 2,
        "Tools by rules interaction": lambda c: (c[(True, True)] - c[(True, False)]) - (c[(False, True)] - c[(False, False)]),
    }
    lines = ["| Effect on share of briefs with an invented ID | Estimate | Bundle-resampled 95% interval |", "|---|---|---|"]
    for name, f in calc.items():
        low, high = cluster_bootstrap(rows, "bundle", lambda s: (lambda e: f(e) if e else None)(effects(s)))
        lines.append(f"| {name} | {f(point):+.1%} | {low:+.1%} to {high:+.1%} |")
    return lines


def attacks(rows):
    groups = sorted({(r["arm"], r["attack"], r["channel"]) for r in rows if r["attack"] not in ("", "none")})
    lines = ["| Arm | Attack | Channel | Manipulated | Reported as suspect | Payload in stage text (screen) | Tool call | Completed effect |",
             "|---|---|---|---|---|---|---|---|"]
    for arm, attack, channel in groups:
        g = [r for r in rows if (r["arm"], r["attack"], r["channel"]) == (arm, attack, channel)]
        n = len(g)
        lines.append(f"| {arm} | {attack} | {channel} | {sum(r.get('attack_outcome') == 'manipulated' for r in g)}/{n} "
                     f"| {sum(r.get('attack_outcome') == 'reported_as_suspect' for r in g)}/{n} "
                     f"| {sum(r['text_attempts'] > 0 for r in g)}/{n} | {sum(r['tool_calls'] > 0 for r in g)}/{n} "
                     f"| {sum(r['effects'] > 0 for r in g)}/{n} |")
    return lines


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--allow-mock", action="store_true")
    args = p.parse_args(argv)
    with open(os.path.join(args.out, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("mock") and not args.allow_mock:
        print("This is a scripted mock run and has no research meaning. Refusing to report it.")
        return 2
    every, rows = load(os.path.join(args.out, "scores.csv"))
    out = ["# Evaluation results", ""]
    if manifest.get("mock"):
        out += ["**MOCK RUN. A scripted model produced these rows, so they test the harness and mean nothing.**", ""]
    out += [f"Model: `{manifest['model']}`. Settings: `{json.dumps(manifest['settings'])}`. "
            f"Commit: `{manifest['git']['commit']}` (dirty: {manifest['git']['dirty']}).",
            f"Runs planned: {len(every)}. Completed: {len(rows)}. Errors: {len(every) - len(rows)}.",
            "Automated screens only until blind coding is complete.", ""]
    for exp in sorted({r["experiment"] for r in rows}):
        group = [r for r in rows if r["experiment"] == exp]
        out += [f"## {exp}", ""] + arm_table(group) + [""]
        out += ["Fact recall by bundle:", ""] + by_bundle(group, "facts_found", "facts_total") + [""]
        if exp == "A_factorial":
            out += factorial(group) + [""]
        if any(r["attack"] not in ("", "none") for r in group):
            out += attacks(group) + [""]
    path = os.path.join(args.out, "results.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
