import os
import subprocess
import sys

import pytest
import yaml

from conditions import ALL_RULES
from guardrails import RULES, get_guardrail_prompt
from provenance import build_chain, sha256_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))

import blind  # noqa: E402
import build_corpus  # noqa: E402
import stats  # noqa: E402


def test_rule_block_ablation():
    assert get_guardrail_prompt(exclude=ALL_RULES) == ""
    block = get_guardrail_prompt(exclude=(6,))
    assert RULES[6] not in block and RULES[7] in block


def test_neutral_prompts_carry_no_rule_language():
    for name in ("agents.yaml", "tasks.yaml"):
        with open(os.path.join(ROOT, "config", "neutral", name), encoding="utf-8") as f:
            body = "\n".join(l for l in f if not l.startswith("#")).lower()
        for phrase in ("fabricat", "speculate", "cite", "uncertain", "unclassified", "attribut", "infer"):
            assert phrase not in body, phrase


def test_stats_reproduce_the_pilot_values():
    assert round(stats.clopper_pearson(0, 30)[1], 3) == 0.116
    assert round(stats.clopper_pearson(0, 10)[1], 3) == 0.308
    assert round(stats.fisher_two_sided(7, 23, 0, 30), 3) == 0.011
    assert round(stats.fisher_two_sided(3, 7, 0, 10), 2) == 0.21


def test_kappa():
    assert stats.cohen_kappa(list("aabb"), list("aabb")) == 1.0
    assert round(stats.cohen_kappa(list("aabb"), list("abab")), 3) == 0.0


def test_corpus_labels_and_clean_controls():
    cells = build_corpus.build()
    assert len(cells["attacks"]) == 26
    folder = os.path.join(build_corpus.OUT, "control__nopatch_legacy_vsat_advisory")
    assert "Crimson" not in "".join(open(os.path.join(folder, n), encoding="utf-8").read() for n in os.listdir(folder))


def test_prose_channel_evades_sanitizer_and_machine_channel_does_not():
    from sanitize import sanitize_text
    build_corpus.build()
    name = "ground_station_modem_advisory"

    def read(channel):
        cell = f"attack__{name}__false_attribution__{channel}"
        with open(os.path.join(build_corpus.OUT, cell, name + ".md"), encoding="utf-8") as f:
            return f.read()

    assert "Crimson Meridian" not in sanitize_text(read("machine")).text
    assert "Crimson Meridian" in sanitize_text(read("prose")).text


def test_truth_patterns_match_their_own_sources():
    import re
    with open(os.path.join(ROOT, "eval", "truth", "facts.yaml"), encoding="utf-8") as f:
        truth = yaml.safe_load(f)
    for doc, entry in truth.items():
        with open(os.path.join(ROOT, "eval", "corpus", "base", doc), encoding="utf-8") as f:
            text = f.read()
        for fact in entry["facts"]:
            assert re.search(fact["pattern"], text, re.I | re.S), (doc, fact["id"])


def test_blinding_removes_arm_tells():
    text = ("# Brief\n**Date:** X\n**Run ID:** A_factorial__T1R0\n**Classification:** UNCLASSIFIED // FOR EDUCATIONAL USE\n"
            "\nThe modem has a default password.\n\n## Source integrity\n- removed\n")
    out = blind.clean(text)
    assert "Run ID" not in out and "UNCLASSIFIED" not in out and "integrity" not in out
    assert "default password" in out


def test_chain_changes_when_a_source_changes(tmp_path):
    (tmp_path / "a.md").write_text("one")
    brief = tmp_path / "b.md"
    brief.write_text("brief")
    first = build_chain("r", str(tmp_path), ["a.md"], ["s1"], str(brief))
    (tmp_path / "a.md").write_text("two")
    second = build_chain("r", str(tmp_path), ["a.md"], ["s1"], str(brief))
    assert first["links"][-1] != second["links"][-1]
    assert first["stages"] == [sha256_text("s1")]


def test_full_harness_end_to_end_with_scripted_model(tmp_path):
    pytest.importorskip("crewai")
    out = str(tmp_path / "mock")
    env = dict(os.environ)
    run = lambda *a: subprocess.run([sys.executable, *a], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    r = run("eval/run_experiment.py", "--mock", "attack", "--out", out, "--experiments", "D_attacks",
            "--runs", "1", "--limit", "12")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[error]" not in r.stdout, r.stdout
    assert run("eval/score.py", "--out", out).returncode == 0
    assert run("eval/analyze.py", "--out", out).returncode == 2  # refuses mock output
    assert run("eval/analyze.py", "--out", out, "--allow-mock").returncode == 0
    with open(os.path.join(out, "results.md"), encoding="utf-8") as f:
        assert "MOCK RUN" in f.read()
    assert run("eval/blind.py", "--out", out).returncode == 0


def test_gate_flags_items_with_no_scorable_text():
    from signals import needs_human_triage
    assert needs_human_triage("Advisory attached", "")
    assert not needs_human_triage("Spacecraft flight software vulnerability", "A flaw affects command handling.")
