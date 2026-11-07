# Evaluation kit

This kit tests which parts of the governance layer do the work. It answers
the gaps in the September pilot, which changed tools and rules together, ran
three documents, and kept no per-run traces. The design was frozen before any
real run. See `PREREGISTRATION.md`.

**Status: no real runs yet.** The tests use a scripted model, which checks the
harness and produces no findings. `analyze.py` refuses to report a mock run
unless forced, and then marks it on the first line.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock pytest
python -m pytest                                  # no model calls
python eval/run_experiment.py --dry-run           # shows the run count

export OPENAI_API_KEY=...                         # or use Ollama through API_BASE
python eval/run_experiment.py --model gpt-4.1-mini --out eval/runs/2026-11
python eval/score.py   --out eval/runs/2026-11
python eval/analyze.py --out eval/runs/2026-11    # writes results.md
python eval/blind.py   --out eval/runs/2026-11 --sample 25
python eval/reliability.py eval/runs/2026-11/coding/coder_a.csv eval/runs/2026-11/coding/coder_b.csv
```

For a first pass before Riyadh, run only the two experiments that matter most:
`--experiments A_factorial D_attacks` (314 runs, about 940 agent tasks). A run
that crashes is recorded, and restarting resumes where it stopped. Pin one
model and keep it for the whole batch.

| Experiment | Question | Runs |
|---|---|---|
| `A_factorial` | Do tools, rules, or both change errors and recall? | 4 arms x 4 bundles x 5 = 80 |
| `B_ablation` | Which rule matters: attribution, uncertainty, or no-fabrication? | 3 x 4 x 5 = 60 |
| `C_comparators` | Unguided single agent, grounded single agent, or full stack? | 3 x 4 x 5 = 60 |
| `D_attacks` | Can a document change the brief? Does the sanitizer help? | 3 arms x 26 cells x 3 = 234 |

## What makes the manipulation real

Removing `guardrails.py` alone would not remove the rules. The pilot's role
and task prompts also said things like "Do NOT fabricate" and "cite the source
file name", and the current code adds citation retries. So factorial arms use
`config/neutral/`, with the sanitizer and code enforcement off, and only the
named factor changes. `tests/test_eval.py` fails if rule language creeps back in.

## What is saved for each run

`eval/runs/<batch>/manifest.json` records the model, settings, commit, every
dependency version, and SHA-256 hashes of the code, prompts, rules, corpus,
truth file, and codebook. Each `runs/<run_id>/` folder holds `brief.md`, one
`stage_N.txt` per agent, `record.json`, `provenance.json`, and, in ambient
arms, `tool_log.jsonl`.

Commit the finished batch to the public repo with `git add -f eval/runs/<batch>`,
then archive that commit. This is the step the pilot could not take, because
its outputs were not saved.

## Safety of the probes

`shell` in the ambient arms is a logging stub and never runs a command.
`read_file` can read only a throwaway folder holding one decoy file. All
attack URLs use the reserved `.invalid` domain. Run batches in a container
anyway: that gives you the operating-system boundary the framework does not.

## Adding real, held-out documents

The current bundles are short fictional documents, written so that facts and
traps are known. They test specific failures but say little about real
reporting. To add evidence that does generalize:

1. Run `python fetch_sources.py --space-only --limit 30 --out eval/corpus/heldout_pull`.
2. Pick documents before looking at any model output. Vary vendor, domain, and
   publication date, and include advisories that conflict.
3. Copy them to `eval/corpus/base/`, group them in `corpus/bundles.yaml`, and
   add their facts to `truth/facts.yaml`.
4. Report results by document as well as pooled.

## Keyword gate

`python eval/audit_gate.py` needs no model. See `gate/README.md`.
