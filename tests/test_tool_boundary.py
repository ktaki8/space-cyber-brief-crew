"""The no-tool claim, checked on the built crew rather than assumed from source."""
import pytest

pytest.importorskip("crewai")

from crew import build_crew  # noqa: E402
from eval_helpers import offline_llm  # noqa: E402


def test_shipped_crew_gives_tools_only_to_collector(tmp_path):
    crew = build_crew(sources_dir="sources", output_file=str(tmp_path / "b.md"), llm=offline_llm())
    tools = {a.role: [t.name for t in (a.tools or [])] for a in crew.agents}
    assert tools["Cyber Threat Intelligence Collector"] == ["Source Document Reader"]
    assert tools["Cyber Threat Analyst"] == []
    assert tools["Intelligence Brief Writer"] == []
    for agent in crew.agents:
        assert not agent.allow_delegation
        assert not agent.allow_code_execution
    assert crew.manager_llm is None and not crew.planning and not crew.memory


def test_runtime_tool_prompt_offers_nothing_to_downstream_agents(tmp_path):
    crew = build_crew(sources_dir="sources", output_file=str(tmp_path / "b.md"), llm=offline_llm())
    for task in crew.tasks[1:]:
        assert not task.tools
