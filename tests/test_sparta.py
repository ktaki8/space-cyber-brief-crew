"""SPARTA mapping: the index, the ID check, and the code-added reference section."""
import pytest

import sparta
from check_brief import check
from conditions import SHIPPED


def test_index_loads_with_attribution():
    idx = sparta.load_index()
    assert idx["sparta_version"].startswith("v3")
    assert len(idx["techniques"]) > 200
    assert "Aerospace Corporation" in idx["notice"]
    rec = sparta.lookup("REC-0001")
    assert rec["name"] == "Gather Spacecraft Design Information"
    assert rec["tactic"] == "Reconnaissance"


def test_subtechniques_point_to_their_parent():
    sub = next(t for t, v in sparta.load_index()["techniques"].items() if v["parent"])
    assert sparta.lookup(sub)["parent"] == sub.split(".")[0]


def test_ids_in_keeps_order_and_ignores_other_frameworks():
    text = "SPARTA: EX-0001, REC-0001.01. ATT&CK T1190. CVE-2024-1234. EX-0001 again."
    assert sparta.ids_in(text) == ["EX-0001", "REC-0001.01"]


def test_unknown_ids_are_caught():
    assert sparta.unknown_ids("SPARTA: EX-0001, EX-9999") == ["EX-9999"]


def test_reference_section_is_built_from_the_index():
    section = sparta.reference_section("SPARTA: EX-0001 and EX-9999")
    assert sparta.REFERENCE_HEADING in section
    assert sparta.lookup("EX-0001")["name"] in section
    assert "EX-9999 | **Not in SPARTA" in section
    assert "permission of The Aerospace Corporation" in section


def test_reference_section_empty_without_ids():
    assert sparta.reference_section("No space techniques here.") == ""


def test_append_reference_replaces_an_old_section():
    once = sparta.append_reference("Item. SPARTA: EX-0001")
    twice = sparta.append_reference(once)
    assert twice.count(sparta.REFERENCE_HEADING) == 1


def test_catalog_covers_every_technique():
    catalog = sparta.catalog_text()
    for tid in sparta.load_index()["techniques"]:
        assert tid in catalog


def test_checker_fails_invented_sparta_id():
    corpus = {"a.md": "Advisory text."}
    brief = "UNCLASSIFIED // FOR EDUCATIONAL USE\n**Date:** x\nSource: a.md\nSPARTA: EX-9999\n"
    results = {(r["check"], r["level"]) for r in check(brief, corpus).results}
    assert ("sparta", "FAIL") in results


def test_checker_passes_real_sparta_id():
    corpus = {"a.md": "Advisory text."}
    brief = "UNCLASSIFIED // FOR EDUCATIONAL USE\n**Date:** x\nSource: a.md\nSPARTA: EX-0001\n"
    results = {(r["check"], r["level"]) for r in check(brief, corpus).results}
    assert ("sparta", "PASS") in results


def test_only_the_shipped_pipeline_uses_sparta():
    assert SHIPPED.sparta
    eval_conditions = pytest.importorskip("eval.conditions")
    for cond in eval_conditions.ARMS.values():
        assert not cond.sparta, cond.name


def test_shipped_crew_prompts_carry_the_catalog(tmp_path):
    pytest.importorskip("crewai")
    from crew import build_crew
    from eval_helpers import offline_llm
    crew = build_crew(sources_dir="sources", output_file=str(tmp_path / "b.md"), llm=offline_llm())
    analyst_task, writer_task = crew.tasks[1], crew.tasks[2]
    assert "SPARTA catalog:" in analyst_task.description
    assert "EX-0001" in analyst_task.description
    assert "SPARTA:" in writer_task.description
    assert crew.agents[1].tools == []  # the catalog is text, not a tool
