"""SPARTA lookups for the pipeline.

SPARTA (Space Attack Research and Tactic Analysis) is The Aerospace
Corporation's matrix of tactics and techniques against spacecraft. The
Analyst may map an item to SPARTA IDs from the shipped catalog. Everything
after that is done in code, not by a model: unknown IDs are caught, and the
official name, tactic, countermeasures, and indicators are looked up from the
index and appended to the brief.

The index is built from the SPARTA STIX bundle by sparta/build_index.py.
The Aerospace Corporation. This work is reproduced and distributed with the
permission of The Aerospace Corporation. See sparta/NOTICE.md.
"""
import json
import os
import re
from functools import lru_cache

INDEX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "index.json")

TACTIC_PREFIXES = ("REC", "RD", "IA", "EX", "PER", "DE", "LM", "EXF", "IMP")
SPARTA_ID = re.compile(r"\b(?:%s)-\d{4}(?:\.\d{2})?\b" % "|".join(TACTIC_PREFIXES))
REFERENCE_HEADING = "## SPARTA Reference"


@lru_cache(maxsize=None)
def load_index(path=INDEX_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def version():
    return load_index()["sparta_version"]


def lookup(tid):
    return load_index()["techniques"].get(tid)


def ids_in(text):
    """SPARTA-style technique IDs in order of first appearance."""
    seen = []
    for m in SPARTA_ID.finditer(text or ""):
        if m.group(0) not in seen:
            seen.append(m.group(0))
    return seen


def unknown_ids(text):
    """IDs shaped like SPARTA technique IDs that SPARTA does not contain."""
    return [t for t in ids_in(text) if lookup(t) is None]


def catalog_text():
    """Every technique, grouped by tactic, for the Analyst's prompt."""
    by_tactic = {}
    for tid, t in load_index()["techniques"].items():
        by_tactic.setdefault(t["tactic"], []).append(f"{tid} {t['name']}")
    order = ["Reconnaissance", "Resource Development", "Initial Access", "Execution",
             "Persistence", "Defense Evasion", "Lateral Movement", "Exfiltration", "Impact"]
    lines = []
    for tactic in order + sorted(set(by_tactic) - set(order)):
        if tactic in by_tactic:
            lines.append(f"{tactic}: " + "; ".join(by_tactic[tactic]))
    return "\n".join(lines)


def analyst_instruction():
    return (
        "\n\nAlso give sparta_mapping: the SPARTA technique IDs (The Aerospace "
        f"Corporation's space attack matrix, {version()}) that match behavior the source "
        "describes against a spacecraft, its ground segment, or its links. Use only IDs from "
        "the catalog below, copied exactly. If no technique clearly fits, write "
        "'sparta_mapping: none'. Never invent an ID.\n\nSPARTA catalog:\n" + catalog_text()
    )


WRITER_INSTRUCTION = (
    "\n\nIn each item, list the analyst's SPARTA technique IDs on a line starting "
    "'SPARTA:', or write 'SPARTA: none identified'. Copy the IDs exactly."
)


def _cm_name(cid):
    return load_index()["countermeasures"].get(cid, cid)


def reference_section(text, max_cms=3, max_indicators=2):
    """Markdown appended to the brief by code: official SPARTA data for each ID."""
    ids = ids_in(text)
    if not ids:
        return ""
    rows = ["| ID | Technique | Tactic | Countermeasures | Indicators to watch |",
            "|---|---|---|---|---|"]
    for tid in ids:
        t = lookup(tid)
        if t is None:
            rows.append(f"| {tid} | **Not in SPARTA {version()}. Verify.** | | | |")
            continue
        cms = "; ".join(f"{c} {_cm_name(c)}" for c in t["countermeasures"][:max_cms]) or "None listed"
        inds = "; ".join(t["indicators"][:max_indicators]) or "None listed"
        rows.append(f"| [{tid}](https://sparta.aerospace.org/technique/{tid.replace('.', '/')}/) "
                    f"| {t['name']} | {t['tactic']} | {cms} | {inds} |")
    return (
        f"\n\n{REFERENCE_HEADING}\n\n"
        f"Looked up in code from SPARTA {version()}, not written by a model. "
        "Countermeasures and indicators are SPARTA's general entries for each technique, "
        "not findings about this incident.\n\n"
        + "\n".join(rows)
        + "\n\n*SPARTA: The Aerospace Corporation. This work is reproduced and distributed "
        "with the permission of The Aerospace Corporation.*\n"
    )


def append_reference(text):
    """Replace any existing reference section, then append a fresh one."""
    body = text.split("\n" + REFERENCE_HEADING)[0].rstrip()
    return body + reference_section(body)
