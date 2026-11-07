"""Freeze everything a reader needs to reconstruct a run: code, prompts,
rules, corpus, dependencies, model settings, and arms."""
import hashlib
import importlib.metadata as md
import json
import os
import platform
import subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACKED = ("crew.py", "conditions.py", "guardrails.py", "sanitize.py", "provenance.py", "check_brief.py",
           "tools/file_reader.py", "config", "eval/corpus/base", "eval/corpus/bundles.yaml",
           "eval/corpus/generated", "eval/attacks/attacks.yaml", "eval/truth/facts.yaml",
           "eval/conditions.py", "eval/probe_tools.py", "eval/score.py", "eval/CODEBOOK.md")


def _files(entry):
    path = os.path.join(ROOT, entry)
    if os.path.isfile(path):
        return [entry]
    found = []
    for base, _, names in os.walk(path):
        found += [os.path.relpath(os.path.join(base, n), ROOT) for n in names if "__pycache__" not in base]
    return sorted(found)


def file_hashes():
    out = {}
    for entry in TRACKED:
        for rel in _files(entry):
            with open(os.path.join(ROOT, rel), "rb") as f:
                out[rel] = hashlib.sha256(f.read()).hexdigest()
    return out


def git_state():
    def run(*args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}


def build(model, settings, arms, mock=False):
    deps = sorted(f"{d.metadata['Name']}=={d.version}" for d in md.distributions())
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "mock": mock,
        "model": model,
        "settings": settings,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git": git_state(),
        "dependencies": deps,
        "files": file_hashes(),
        "arms": arms,
    }


def write(path, manifest):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
