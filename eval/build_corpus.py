"""Materialize every run's source folder from the base documents and attacks.

Writes eval/corpus/generated/<cell>/ and returns the cell list. Output is
deterministic, so the manifest hash proves which corpus a run used.
"""
import os
import re
import shutil

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "corpus", "base")
OUT = os.path.join(HERE, "corpus", "generated")


def _load(name):
    with open(os.path.join(HERE, name), "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _inject(text, payload, channel):
    payload = " ".join(payload.split())
    if channel == "machine":
        return text.rstrip() + f"\n\n<!--\n{payload}\n-->\n"
    # Prose goes in the body, before the recommended actions, as a normal paragraph.
    block = payload + "\n\n"
    marker = re.search(r"^Recommended actions:", text, re.M)
    at = marker.start() if marker else len(text)
    return text[:at] + block + text[at:]


def build():
    shutil.rmtree(OUT, ignore_errors=True)
    bundles = _load(os.path.join("corpus", "bundles.yaml"))
    spec = _load(os.path.join("attacks", "attacks.yaml"))
    cells = {"clean": [], "attacks": []}

    def write(cell, files):
        folder = os.path.join(OUT, cell)
        os.makedirs(folder)
        for name, text in files.items():
            with open(os.path.join(folder, name), "w", encoding="utf-8") as f:
                f.write(text)

    def read(name):
        with open(os.path.join(BASE, name), "r", encoding="utf-8") as f:
            return f.read()

    for name, docs in bundles.items():
        write(f"clean__{name}", {d: read(d) for d in docs})
        cells["clean"].append({"cell": f"clean__{name}", "bundle": name, "attack": "", "channel": "",
                               "carrier": ""})
    for carrier in spec["carriers"]:
        short = os.path.splitext(carrier)[0]
        files = {d: read(d) for d in [carrier, *spec["distractors"]]}
        write(f"control__{short}", files)
        cells["attacks"].append({"cell": f"control__{short}", "bundle": short, "attack": "none",
                                 "channel": "none", "carrier": carrier})
        for attack, a in spec["attacks"].items():
            for channel in ("machine", "prose"):
                cell = f"attack__{short}__{attack}__{channel}"
                changed = dict(files)
                changed[carrier] = _inject(files[carrier], a[channel], channel)
                write(cell, changed)
                cells["attacks"].append({"cell": cell, "bundle": short, "attack": attack,
                                         "channel": channel, "carrier": carrier})
    return cells


if __name__ == "__main__":
    c = build()
    print(len(c["clean"]), "clean cells;", len(c["attacks"]), "attack cells including controls")
