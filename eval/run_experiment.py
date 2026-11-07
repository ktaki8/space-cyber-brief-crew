"""Run the frozen experiments and save everything each run produced.

    python eval/run_experiment.py --dry-run
    MODEL=gpt-4.1-mini python eval/run_experiment.py --out eval/runs/2026-11 --experiments A_factorial D_attacks

Runs are shuffled with a fixed seed, so time and rate-limit drift do not line
up with an arm. A run that finished is skipped on restart, so an interrupted
batch resumes. Failed runs are recorded, never dropped.
"""
import argparse
import dataclasses
import json
import os
import random
import shutil
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
os.environ.setdefault("OTEL_SDK_DISABLED", "true")          # CrewAI telemetry off
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")

import build_corpus  # noqa: E402
import manifest as mf  # noqa: E402

sys.path.pop(0)
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("eval_conditions", os.path.join(ROOT, "eval", "conditions.py"))
ec = importlib.util.module_from_spec(_spec)
sys.modules["eval_conditions"] = ec  # dataclasses and pickling look the module up by name
_spec.loader.exec_module(ec)


def plan(experiments, cells, runs_override=None):
    jobs = []
    for exp in experiments:
        arms, kind, runs = ec.EXPERIMENTS[exp]
        runs = runs_override or runs
        for arm in arms:
            for cell in cells[kind]:
                for i in range(runs):
                    run_id = f"{exp}__{arm.name}__{cell['cell']}__r{i + 1:02d}"
                    jobs.append({"run_id": run_id, "experiment": exp, "arm": arm.name, "repeat": i + 1, **cell})
    return jobs


def seed_supported(model):
    """Anthropic's API has no seed parameter; sending one makes the call fail.
    The manifest records the seed as null for such models."""
    m = (model or "").lower()
    return not (m.startswith("anthropic/") or m.startswith("claude"))


def build_llm(args):
    if args.mock:
        from mock_llm import MockLLM
        return MockLLM("attack" if args.mock == "attack" else "clean")
    from crewai import LLM
    kwargs = {"model": args.model, "temperature": args.temperature}
    if seed_supported(args.model):
        kwargs["seed"] = args.seed
    if os.getenv("API_BASE"):
        kwargs["base_url"] = os.getenv("API_BASE")
    return LLM(**kwargs)


def run_one(job, out_dir, args):
    from crew import build_crew
    arm = ec.ARMS[job["arm"]]
    run_dir = os.path.join(out_dir, "runs", job["run_id"])
    if os.path.isfile(os.path.join(run_dir, "record.json")):
        return "skip"
    shutil.rmtree(run_dir, ignore_errors=True)
    os.makedirs(run_dir)
    sources = os.path.join(build_corpus.OUT, job["cell"])
    # CrewAI rejects output paths outside the working tree, so write inside
    # output/ and move the brief into the run folder afterward.
    working_brief = os.path.join("output", "eval_tmp", job["run_id"] + ".md")
    os.makedirs(os.path.dirname(working_brief), exist_ok=True)
    brief_path = os.path.join(run_dir, "brief.md")
    extra = []
    if arm.tools == "ambient":
        from probe_tools import make_probe_tools
        extra = make_probe_tools(run_dir)
    started = time.time()
    record = dict(job, status="ok", condition=dataclasses.asdict(arm))
    try:
        crew = build_crew(sources_dir=sources, output_file=working_brief, sanitize=arm.sanitize,
                          condition=arm, llm=build_llm(args), extra_tools=extra, run_id=job["run_id"])
        record["tools_by_agent"] = {a.role: [t.name for t in (a.tools or [])] for a in crew.agents}
        result = crew.kickoff()
        stages = [t.raw for t in result.tasks_output]
        for i, text in enumerate(stages):
            with open(os.path.join(run_dir, f"stage_{i + 1}.txt"), "w", encoding="utf-8") as f:
                f.write(text or "")
        if os.path.isfile(working_brief):
            shutil.move(working_brief, brief_path)
        else:
            with open(brief_path, "w", encoding="utf-8") as f:
                f.write(stages[-1] or "")
        from provenance import write_chain
        from tools.file_reader import list_source_files
        write_chain(os.path.join(run_dir, "provenance.json"), job["run_id"], sources,
                    list_source_files(sources), stages, brief_path)
    except Exception:
        record["status"] = "error"
        record["error"] = traceback.format_exc()
    record["seconds"] = round(time.time() - started, 1)
    with open(os.path.join(run_dir, "record.json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return record["status"]


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join("eval", "runs", "latest"))
    p.add_argument("--experiments", nargs="+", default=list(ec.EXPERIMENTS), choices=list(ec.EXPERIMENTS))
    p.add_argument("--model", default=os.getenv("MODEL"), help="exact model name; required for a real run")
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=20261103)
    p.add_argument("--runs", type=int, help="override runs per cell (for smoke tests only)")
    p.add_argument("--limit", type=int, help="stop after this many runs")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--mock", nargs="?", const="clean", choices=["clean", "attack"])
    args = p.parse_args(argv)

    os.chdir(ROOT)
    cells = build_corpus.build()
    jobs = plan(args.experiments, cells, args.runs)
    random.Random(args.seed).shuffle(jobs)
    counts = {}
    for j in jobs:
        counts[j["experiment"]] = counts.get(j["experiment"], 0) + 1
    print(f"{len(jobs)} runs: {counts}")
    if args.dry_run:
        return 0
    if not args.model and not args.mock:
        print("ERROR: pin the model with --model or MODEL. An unpinned default is what made the pilot hard to reconstruct.")
        return 2

    os.makedirs(args.out, exist_ok=True)
    settings = {"temperature": args.temperature,
                "seed": args.seed if seed_supported(args.model) else None,
                "api_base": os.getenv("API_BASE")}
    arms = {n: dataclasses.asdict(c) for n, c in ec.ARMS.items()}
    mf.write(os.path.join(args.out, "manifest.json"),
             mf.build(args.mock and "mock-scripted" or args.model, settings, arms, mock=bool(args.mock)))
    with open(os.path.join(args.out, "plan.json"), "w", encoding="utf-8") as f:
        json.dump(jobs, f, indent=2)

    done = errors = 0
    for job in jobs[:args.limit]:
        status = run_one(job, args.out, args)
        done += status != "skip"
        errors += status == "error"
        print(f"[{status}] {job['run_id']}", flush=True)
    print(f"Finished {done} run(s), {errors} error(s). Next: python eval/score.py --out {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
