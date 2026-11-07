import os
import re
import yaml
from datetime import datetime, timezone
from crewai import Agent, Task, Crew, Process, LLM
from tools.file_reader import FileReaderTool, SOURCES_DIR, list_source_files
from guardrails import get_guardrail_prompt
from sanitize import sanitize_text
from check_brief import citation_status
from plain_output import strip_emoji
from conditions import Condition, SHIPPED, TOPOLOGY_SINGLE
import sparta
from provenance import new_run_id

DEFAULT_OUTPUT = os.path.join("output", "daily_brief.md")
GUARDRAIL_RETRIES = 2

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


MARKING_LINE = "**Classification:** UNCLASSIFIED // FOR EDUCATIONAL USE"
MARKING_TEST = re.compile(r"UNCLASSIFIED\s*//\s*FOR\s+EDUCATIONAL\s+USE", re.I)


def stamp_run_metadata(text, run_id):
    """Add the run ID and, if missing, the classification banner in code.

    Metadata comes from the runtime, not from the model. The banner is the
    exact string rule 9 requires, so a compliant brief is left unchanged.
    """
    lines = text.split("\n")
    at = next((i for i, line in enumerate(lines) if line.lstrip().startswith("**Date:**")), None)
    if at is None:
        at = 0
    insert = [f"**Run ID:** {run_id}  "]
    if not MARKING_TEST.search(text):
        insert.append(MARKING_LINE)
    lines[at + 1:at + 1] = insert
    return "\n".join(lines)


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


def build_crew(sources_dir=None, output_file=DEFAULT_OUTPUT, sanitize=True,
               condition: Condition = SHIPPED, llm=None, extra_tools=None, run_id=None):
    """Build the crew. With the defaults this is the shipped, governed pipeline.

    condition, llm, and extra_tools exist for the evaluation (eval/): they
    switch the prompts, rule set, and code enforcement, and hand the ambient
    baseline its logged probe tools. Nothing a model reads can set them.
    """
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    config_dir = condition.config_dir
    agent_configs = load_yaml(os.path.join(config_dir, "agents.yaml"))
    task_configs = load_yaml(os.path.join(config_dir, "tasks.yaml"))
    guardrails = get_guardrail_prompt(exclude=condition.excluded_rules)
    run_id = run_id or new_run_id()
    tle_catalog = None
    if condition.sparta and os.getenv("ORBITAL_TLE"):
        from orbital import Catalog  # space-domain checks travel with the shipped pipeline
        tle_catalog = Catalog.from_file(os.getenv("ORBITAL_TLE"))

    resolved_sources = resolve_sources_dir(sources_dir)
    file_reader = FileReaderTool(sources_dir=resolved_sources, sanitize=sanitize)
    quarantined = quarantined_sources(resolved_sources) if sanitize else {}
    source_names = list_source_files(resolved_sources)
    llm = llm if llm is not None else build_llm()
    llm_kwargs = {"llm": llm} if llm is not None else {}
    extra_tools = list(extra_tools or [])

    if condition.topology == TOPOLOGY_SINGLE:
        return _build_single_agent(agent_configs, task_configs, guardrails, file_reader,
                                   output_file, llm_kwargs)

    collector = Agent(
        role=agent_configs["collector"]["role"],
        goal=agent_configs["collector"]["goal"],
        backstory=agent_configs["collector"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=[file_reader] + extra_tools,
        **llm_kwargs,
    )

    analyst = Agent(
        role=agent_configs["analyst"]["role"],
        goal=agent_configs["analyst"]["goal"],
        backstory=agent_configs["analyst"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=list(extra_tools),
        **llm_kwargs,
    )

    writer = Agent(
        role=agent_configs["writer"]["role"],
        goal=agent_configs["writer"]["goal"],
        backstory=agent_configs["writer"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=list(extra_tools),
        **llm_kwargs,
    )

    collect_task = Task(
        description=task_configs["collect_threats"]["description"],
        expected_output=task_configs["collect_threats"]["expected_output"],
        agent=collector,
    )

    analyze_task = Task(
        description=task_configs["analyze_threats"]["description"]
        + (sparta.analyst_instruction() if condition.sparta else ""),
        expected_output=task_configs["analyze_threats"]["expected_output"],
        agent=analyst,
        context=[collect_task],
    )

    def enforce_brief_rules(output):
        """Task guardrail, run in code before the brief is saved.

        Rejects a brief that cites source files that do not exist, or cites
        none at all, and sends it back to the Writer with the reason (up to
        GUARDRAIL_RETRIES times). Then unwraps code fences, stamps the real
        date, and makes sure any quarantined source is disclosed.
        """
        text = strip_emoji(strip_code_fence(output.raw))
        unknown, uncited = citation_status(text, set(source_names))
        problem, detail = None, ""
        if unknown:
            problem = "The brief cites sources that do not exist: " + ", ".join(unknown) + "."
            detail = " Rewrite it citing only these exact file names: " + ", ".join(source_names) + "."
        elif source_names and len(uncited) == len(source_names):
            problem = "The brief cites no sources."
            detail = " Cite the exact source file name in every item, choosing from: " + ", ".join(source_names) + "."
        bad_sparta = sparta.unknown_ids(text) if condition.sparta else []
        if not problem and bad_sparta:
            problem = "The brief uses SPARTA IDs that do not exist: " + ", ".join(bad_sparta) + "."
            detail = " Use only the IDs the analyst gave, copied exactly, or write 'SPARTA: none identified'."
        if not problem and tle_catalog is not None:
            import orbital
            wrong = [c for c in orbital.verify(text, tle_catalog) if c.verdict == orbital.CONTRADICTED]
            if wrong:
                problem = "Orbital claims contradicted by tracking data: " + " ".join(
                    f'"{c.sentence}" ({c.detail})' for c in wrong)
                detail = " Remove these claims or report them only as unverified source statements."
        if problem and write_task.retry_count < GUARDRAIL_RETRIES:
            return (False, problem + detail)
        if problem:  # retries used up: keep the brief, but say so at the top
            text = f"> **Attribution warning:** {problem} Verify every item against the sources.\n\n" + text
        text = stamp_run_metadata(stamp_brief_date(text, today), run_id)
        text = ensure_integrity_note(text, quarantined)
        if condition.sparta:
            text = sparta.append_reference(text)
        if tle_catalog is not None:
            import orbital
            text = orbital.append_report(text, tle_catalog)
        return (True, text)

    # These two instructions belong to the code-enforced layer, so an arm with
    # that layer off must not receive them either.
    write_contract = (
        f"\n\nThe date of this brief is {today}. Write it as **Date:** {today}."
        " Do not use any other date for the brief itself."
        "\n\nThe only valid source file names are: " + ", ".join(source_names)
        + ". Copy them exactly; never rename, shorten, or invent a file name."
    ) if condition.code_enforcement else ""

    write_task = Task(
        description=task_configs["write_brief"]["description"] + write_contract
        + (sparta.WRITER_INSTRUCTION if condition.sparta else ""),
        expected_output=task_configs["write_brief"]["expected_output"],
        agent=writer,
        context=[analyze_task],
        output_file=output_file,
        **({"guardrail": enforce_brief_rules, "guardrail_max_retries": GUARDRAIL_RETRIES}
           if condition.code_enforcement else {}),
    )

    crew = Crew(
        agents=[collector, analyst, writer],
        tasks=[collect_task, analyze_task, write_task],
        process=Process.sequential,
        verbose=True,
    )

    return crew


def _build_single_agent(agent_configs, task_configs, guardrails, file_reader, output_file, llm_kwargs):
    """Grounded single-agent comparator: one agent reads the sources and writes the brief."""
    analyst = Agent(
        role=agent_configs["single"]["role"],
        goal=agent_configs["single"]["goal"],
        backstory=agent_configs["single"]["backstory"] + "\n\n" + guardrails,
        verbose=True,
        allow_delegation=False,
        tools=[file_reader],
        **llm_kwargs,
    )
    task = Task(
        description=task_configs["single_brief"]["description"],
        expected_output=task_configs["single_brief"]["expected_output"],
        agent=analyst,
        output_file=output_file,
    )
    return Crew(agents=[analyst], tasks=[task], process=Process.sequential, verbose=True)
