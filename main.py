import argparse
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

from sanitize import sanitize_text
from tools.file_reader import list_source_files

OUTPUT_ROOT = os.path.realpath("output")


def uses_local_model() -> bool:
    return (os.getenv("MODEL") or "").lower().startswith("ollama/")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Run the Collector -> Analyst -> Writer pipeline.")
    p.add_argument("--sources", help="source folder (default: BRIEF_SOURCES_DIR or sources/)")
    p.add_argument("--output", default=os.path.join("output", "daily_brief.md"),
                   help="where to write the brief; must be inside output/ (default: output/daily_brief.md)")
    p.add_argument("--no-sanitize", action="store_true",
                   help="turn off the source sanitizer (for before/after comparisons only)")
    return p.parse_args(argv)


def sanitization_report(sources_dir, source_files, report_path):
    """Run the sanitizer the Collector will use and save what it removed for human review."""
    entries = []
    for name in source_files:
        with open(os.path.join(sources_dir, name), "r", encoding="utf-8") as f:
            result = sanitize_text(f.read())
        for finding in result.findings:
            entries.append({"file": name, "kind": finding.kind, "reason": finding.reason,
                            "removed_text": finding.removed_text})
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({"sources": os.path.relpath(sources_dir), "quarantined": entries}, f, indent=2)
    return entries


def main(argv=None):
    load_dotenv()
    args = parse_args(argv)

    if not uses_local_model() and not (os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
        print("ERROR: No API key found.")
        print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY in your .env file,")
        print("or set MODEL=ollama/<model> to run on a local model.")
        sys.exit(1)

    from crew import resolve_sources_dir
    sources_dir = resolve_sources_dir(args.sources)
    if not os.path.isdir(sources_dir):
        print(f"ERROR: source folder not found: {sources_dir}")
        sys.exit(1)

    source_files = list_source_files(sources_dir)
    if not source_files:
        print(f"ERROR: No .txt or .md source documents found in {sources_dir}.")
        sys.exit(1)

    # Guardrail rule 5: output goes to output/ only. Enforced here, not just prompted.
    output_path = os.path.realpath(args.output)
    if os.path.commonpath([output_path, OUTPUT_ROOT]) != OUTPUT_ROOT:
        print("ERROR: --output must be inside the output/ folder.")
        sys.exit(1)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sanitize = not args.no_sanitize
    report_path = os.path.splitext(output_path)[0] + "_sanitization.json"
    quarantined = sanitization_report(sources_dir, source_files, report_path) if sanitize else []

    print("=" * 60)
    print("  SPACE-CYBER BRIEF CREW")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Model:   {os.getenv('MODEL') or 'CrewAI default'}")
    print(f"  Sources: {os.path.relpath(sources_dir)} ({len(source_files)} document(s))")
    if sanitize:
        print(f"  Sanitizer: ON, {len(quarantined)} item(s) quarantined")
        for q in quarantined:
            print(f"    - {q['file']}: {q['reason']}")
        if quarantined:
            print(f"    Review: {os.path.relpath(report_path)}")
    else:
        print("  Sanitizer: OFF (--no-sanitize)")
    print("=" * 60)
    print()

    from crew import build_crew
    crew = build_crew(sources_dir=sources_dir, output_file=os.path.relpath(output_path), sanitize=sanitize)
    result = crew.kickoff()

    print()
    print("=" * 60)
    print("  CREW RUN COMPLETE")
    print(f"  Output: {os.path.relpath(output_path)}")
    print(f"  Check:  python check_brief.py {os.path.relpath(output_path)} --sources {os.path.relpath(sources_dir)}")
    print("=" * 60)
    return result


if __name__ == "__main__":
    main()
