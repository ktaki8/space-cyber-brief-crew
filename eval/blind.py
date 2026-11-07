"""Prepare blind double coding of atomic claims.

Each brief gets a random code, and text that reveals the arm is stripped: run
ID, date, the marking banner, the integrity section, and attribution warnings.
A governed brief can still be guessable from its style, so report any arm
guesses the coders make. Claims are split per sentence, and coders may split
further. The key stays with the study lead until coding is locked.
"""
import argparse
import csv
import json
import os
import random
import re
import secrets

STRIP = [
    r"^\*\*Run ID:\*\*.*$", r"^\*\*Date:\*\*.*$", r"^\*\*Classification:\*\*.*$",
    r"^.*UNCLASSIFIED\s*//\s*FOR\s+EDUCATIONAL\s+USE.*$", r"^> \*\*Attribution warning:.*$",
]
SECTION = re.compile(r"\n#{1,3} Source integrity.*?(?=\n#{1,3} |\Z)", re.S | re.I)
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def clean(text):
    text = SECTION.sub("\n", text)
    for pattern in STRIP:
        text = re.sub(pattern, "", text, flags=re.M | re.I)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def claims(text):
    out = []
    for part in SENTENCE.split(text):
        part = part.strip(" -*#\t")
        if len(part.split()) >= 4:
            out.append(part)
    return out


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--coders", nargs=2, default=["coder_a", "coder_b"])
    p.add_argument("--sample", type=int, help="code a stratified sample of this many briefs per arm")
    p.add_argument("--seed", type=int, default=20261103)
    args = p.parse_args(argv)
    rng = random.Random(args.seed)
    runs_dir = os.path.join(args.out, "runs")
    records = []
    for name in sorted(os.listdir(runs_dir)):
        with open(os.path.join(runs_dir, name, "record.json"), encoding="utf-8") as f:
            rec = json.load(f)
        if rec.get("status") == "ok":
            records.append(rec)
    if args.sample:
        chosen = []
        for arm in sorted({r["arm"] for r in records}):
            group = [r for r in records if r["arm"] == arm]
            rng.shuffle(group)
            chosen += group[:args.sample]
        records = chosen
    rng.shuffle(records)
    coding = os.path.join(args.out, "coding")
    os.makedirs(os.path.join(coding, "briefs"), exist_ok=True)
    key, sheet = [], []
    for rec in records:
        code = "B-" + secrets.token_hex(4)
        with open(os.path.join(runs_dir, rec["run_id"], "brief.md"), encoding="utf-8") as f:
            text = clean(f.read())
        with open(os.path.join(coding, "briefs", code + ".md"), "w", encoding="utf-8") as f:
            f.write(text)
        key.append({"code": code, "run_id": rec["run_id"], "arm": rec["arm"], "cell": rec["cell"]})
        for i, claim in enumerate(claims(text), 1):
            sheet.append({"brief": code, "claim_id": f"{code}-{i:03d}", "claim": claim})
    rng.shuffle(sheet)
    columns = ["brief", "claim_id", "claim", "is_claim", "support", "citation_identity",
               "fabricated", "manipulated", "uncertainty_ok", "notes"]
    for coder in args.coders:
        with open(os.path.join(coding, f"{coder}.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=columns, restval="")
            w.writeheader()
            w.writerows(sheet)
    with open(os.path.join(coding, "KEY_do_not_share_with_coders.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["code", "run_id", "arm", "cell"])
        w.writeheader()
        w.writerows(key)
    print(f"{len(records)} briefs, {len(sheet)} candidate claims. Sheets in {coding}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
