"""Run IDs and the source-to-brief hash chain.

The chain records which exact inputs and intermediate outputs produced a
brief. It proves identity, not truth: it does not show that a claim follows
from its source, that a source is credible, or who handled the files.
"""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone


def new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path):
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


def build_chain(run_id, sources_dir, source_files, stage_outputs, brief_path):
    chain = {
        "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "sources": {name: sha256_file(os.path.join(sources_dir, name)) for name in source_files},
        "stages": [sha256_text(text or "") for text in stage_outputs],
        "brief": sha256_file(brief_path) if os.path.isfile(brief_path) else None,
    }
    previous = ""
    links = []
    for item in [json.dumps(chain["sources"], sort_keys=True), *chain["stages"], chain["brief"] or ""]:
        previous = sha256_text(previous + item)
        links.append(previous)
    chain["links"] = links
    return chain


def write_chain(path, run_id, sources_dir, source_files, stage_outputs, brief_path):
    chain = build_chain(run_id, sources_dir, source_files, stage_outputs, brief_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)
    return chain
