import os
import re
import yaml
from datetime import datetime, timezone
from crewai import Agent, Task, Crew, Process, LLM
from tools.file_reader import FileReaderTool, SOURCES_DIR
from guardrails import get_guardrail_prompt

DEFAULT_OUTPUT = os.path.join("output", "daily_brief.md")

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def strip_code_fence(text):
    """Remove a ```markdown ... ``` wrapper so the saved brief renders."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[:-3]
    return stripped.strip() + "\n"


def stamp_brief_date(text, today):
    """Force the brief's date line to the real run date.

    The model is told the date, but compliance with instructions is
    probabilistic, so the date is also enforced in code. If the brief has a
    **Date:** line, its value is replaced; if not, one is added under the title.
    """
    new_text, count = re.subn(
        r"(\*\*Date:\*\*[ \t]*)[^\n]*?([ \t]*)$",
        lambda m: m.group(1) + today + m.group(2),
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count:
        return new_text

    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("# "):
            lines.insert(i + 1, f"**Date:** {today}  ")
            return "\n".join(lines)
    return f"**Date:** {today}\n\n" + text


def resolve_sources_dir(sources_dir=None):
    """Operator choice: argument, then BRIEF_SOURCES_DIR, then sources/."""
    chosen = sources_dir or os.getenv("BRIEF_SOURCES_DIR") or SOURCES_DIR
    return os.path.realpath(chosen)


def build_llm():
    """Model from .env. Returns None to let CrewAI use its default.

    MODEL=gpt-4o-mini                       (OpenAI, needs OPENAI_API_KEY)
    MODEL=ollama/llama3.1:8b                (local, no key, no internet)
    API_BASE=http://gpu-box:11434           (optional: non-default server)
    """
    model = os.getenv("MODEL")
    if not model:
        return None
    kwargs = {"model": model}
    base_url = os.getenv("API_BASE")
    if base_url:
        kwargs["base_url"] = base_url
    return LLM(**kwargs)


def build_crew(sources_dir=None, output_file=DEFAULT_OUTPUT, sanitize=True):
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    agent_configs = load_yaml("config/agents.yaml")
    task_configs = load_yaml("config/tasks.yaml")
    guardrails = get_guardrail_prompt()

    file_reader = FileReaderTool(sources_dir=resolve_sources_dir(sources_dir), sanitize=sanitize)
    llm = build_llm()
    llm_kwargs = {"llm": llm} if llm is not None else {}

    collector = Agent(
        role=agent_configs["collector"]["role"],
        goal=agent_configs["collector"]["goal"],
        backstory=agent_configs["collector"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=[file_reader],
        **llm_kwargs,
    )

    analyst = Agent(
        role=agent_configs["analyst"]["role"],
        goal=agent_configs["analyst"]["goal"],
        backstory=agent_configs["analyst"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=[],
        **llm_kwargs,
    )

    writer = Agent(
        role=agent_configs["writer"]["role"],
        goal=agent_configs["writer"]["goal"],
        backstory=agent_configs["writer"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=[],
        **llm_kwargs,
    )

    collect_task = Task(
        description=task_configs["collect_threats"]["description"],
        expected_output=task_configs["collect_threats"]["expected_output"],
        agent=collector,
    )

    analyze_task = Task(
        description=task_configs["analyze_threats"]["description"],
        expected_output=task_configs["analyze_threats"]["expected_output"],
        agent=analyst,
        context=[collect_task],
    )

    def enforce_run_date(output):
        """Task guardrail: unwrap code fences and stamp the real date before saving."""
        return (True, stamp_brief_date(strip_code_fence(output.raw), today))

    write_task = Task(
        description=task_configs["write_brief"]["description"]
        + f"\n\nThe date of this brief is {today}. Write it as **Date:** {today}."
        " Do not use any other date for the brief itself.",
        expected_output=task_configs["write_brief"]["expected_output"],
        agent=writer,
        context=[analyze_task],
        output_file=output_file,
        guardrail=enforce_run_date,
    )

    crew = Crew(
        agents=[collector, analyst, writer],
        tasks=[collect_task, analyze_task, write_task],
        process=Process.sequential,
        verbose=True,
    )

    return crew
