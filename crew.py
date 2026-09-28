import os
import re
import yaml
from datetime import datetime, timezone
from crewai import Agent, Task, Crew, Process, LLM
from tools.file_reader import FileReaderTool, SOURCES_DIR, list_source_files
from guardrails import get_guardrail_prompt
from sanitize import sanitize_text

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


def quarantined_sources(sources_dir):
    """{file name: [reasons]} for every source the sanitizer changes."""
    found = {}
    for name in list_source_files(sources_dir):
        with open(os.path.join(sources_dir, name), "r", encoding="utf-8") as f:
            findings = sanitize_text(f.read()).findings
        reasons = [x.reason.split(" (")[0] for x in findings if x.kind != "invisible_chars"]
        if reasons:
            found[name] = reasons
    return found


def ensure_integrity_note(text, quarantined):
    """If sources were quarantined and the brief does not say so, say so.

    The Writer is asked to add this section, but compliance is
    probabilistic, so the disclosure is also guaranteed in code.
    """
    if not quarantined or "quarantin" in text.lower():
        return text
    lines = ["", "## Source integrity", ""]
    for name, reasons in sorted(quarantined.items()):
        lines.append(f"- `{name}`: {'; '.join(sorted(set(reasons)))} removed as a suspected prompt injection.")
    lines += ["", "The source sanitizer quarantined this content before analysis, and it was not used "
              "in this brief. The removed text is saved in the sanitization report for human review.", ""]
    return text.rstrip("\n") + "\n" + "\n".join(lines)


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

    resolved_sources = resolve_sources_dir(sources_dir)
    file_reader = FileReaderTool(sources_dir=resolved_sources, sanitize=sanitize)
    quarantined = quarantined_sources(resolved_sources) if sanitize else {}
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
        """Task guardrail: unwrap code fences, stamp the real date, and make
        sure any quarantined source is disclosed, before saving."""
        text = stamp_brief_date(strip_code_fence(output.raw), today)
        return (True, ensure_integrity_note(text, quarantined))

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
