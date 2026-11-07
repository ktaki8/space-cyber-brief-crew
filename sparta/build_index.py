"""Build the compact SPARTA index the pipeline ships with.

Reads the SPARTA STIX 2.1 bundle (download it from
https://sparta.aerospace.org/resources/working-with) and writes
sparta/data/index.json: each technique's name and tactic, the SPARTA
countermeasures related to it, and the SPARTA indicators that point to it.

    python -m sparta.build_index path/to/sparta_data_v3.2.json
"""
import argparse
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "index.json")


def sparta_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "sparta" and ref.get("external_id"):
            return ref["external_id"]
    return obj.get("x_mitre_id")


def build(bundle):
    objects = bundle["objects"]
    by_ref = {o["id"]: o for o in objects}
    version = next((o.get("x_sparta_version") for o in objects
                    if o["type"] == "x-sparta-collection"), None)

    techniques, countermeasures = {}, {}
    for o in objects:
        if o["type"] == "attack-pattern":
            phases = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                      if p.get("kill_chain_name") == "sparta"]
            if not phases:
                continue  # threat entries (SV-*) are not techniques
            tid = sparta_id(o)
            techniques[tid] = {
                "name": o["name"],
                "tactic": phases[0],
                "parent": tid.split(".")[0] if "." in tid else None,
                "countermeasures": [],
                "indicators": [],
            }
        elif o["type"] == "course-of-action":
            cid = sparta_id(o)
            if cid and re.fullmatch(r"CM\d{4}", cid):
                countermeasures[cid] = o["name"]

    for o in objects:
        if o["type"] != "relationship":
            continue
        src, dst = by_ref.get(o["source_ref"]), by_ref.get(o["target_ref"])
        if not src or not dst or dst["type"] != "attack-pattern":
            continue
        tech = techniques.get(sparta_id(dst))
        if tech is None:
            continue
        if src["type"] == "course-of-action":
            cid = sparta_id(src)
            if cid in countermeasures and cid not in tech["countermeasures"]:
                tech["countermeasures"].append(cid)
        elif src["type"] == "indicator" and o.get("relationship_type") == "indicates":
            if src["name"] not in tech["indicators"]:
                tech["indicators"].append(src["name"])

    for tech in techniques.values():
        tech["countermeasures"].sort()
        tech["indicators"].sort()
    return {
        "sparta_version": version,
        "source": "https://sparta.aerospace.org",
        "notice": "The Aerospace Corporation. This work is reproduced and distributed "
                  "with the permission of The Aerospace Corporation.",
        "techniques": dict(sorted(techniques.items())),
        "countermeasures": dict(sorted(countermeasures.items())),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("stix", help="SPARTA STIX 2.1 bundle (JSON)")
    p.add_argument("--out", default=OUT)
    args = p.parse_args(argv)
    with open(args.stix, encoding="utf-8") as f:
        index = build(json.load(f))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"SPARTA {index['sparta_version']}: {len(index['techniques'])} techniques, "
          f"{len(index['countermeasures'])} countermeasures -> {args.out}")


if __name__ == "__main__":
    main()
