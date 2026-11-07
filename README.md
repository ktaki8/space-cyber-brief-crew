# Space-Cyber Brief Crew

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22839735.svg)](https://doi.org/10.5281/zenodo.22839735)

Space-segment cyber reporting is scattered across advisories, notices, and forums, and triaging it by hand is slow. Space-Cyber Brief Crew is a governed multi-agent pipeline, built with CrewAI, that turns a folder of those documents into a structured daily intelligence brief, and then **measures** whether the agents followed their analytic rules instead of assuming they did.

It is built for threat intelligence analysts, SOC teams, and researchers working on space, ground, and link segment security. It runs on a hosted model or fully offline on a local one.

It accompanies the paper *Governing the Intelligence Loop: Architectural Mitigations for Epistemic Fragility in Autonomous Space-Cyber Threat Analysis* (Taki, 2026; preprint, [doi:10.5281/zenodo.22839735](https://doi.org/10.5281/zenodo.22839735)).

## What it does

- **Writes the brief.** Three agents collect, analyze, and write: severity, confidence, MITRE ATT&CK or ATLAS mappings, and What Happened / Why It Matters / What to Watch for each item.
- **Contains injected instructions.** Only the Collector has a tool, and it can only read one operator-chosen folder. The agents that interpret the content have no tools at all.
- **Quarantines known injection patterns.** A source sanitizer removes hidden HTML comments, invisible characters, and passages addressed to AI systems before any model reads them, and logs what it removed for review.
- **Checks its own output.** `check_brief.py` flags invented CVE IDs, citations of files that don't exist, missing classification markings, and canary strings planted by prompt-injection tests.
- **Runs on real reporting.** `fetch_sources.py` pulls current CISA advisories into a corpus with provenance recorded for every document.

## Sample output

An excerpt from a brief generated on September 28, 2026 from live CISA advisories. Full brief: [`demo/fallback_brief.md`](demo/fallback_brief.md).

<details>
<summary>Show the excerpt</summary>

**Date:** September 28, 2026<br>
**Classification:** UNCLASSIFIED // FOR EDUCATIONAL USE

---

### Executive Summary

September 28's briefing highlights critical vulnerabilities across multiple critical infrastructure sectors including Industrial Control Systems, Satellite Communications, Physical Security, Electrical Power, and Transportation. The Mitsubishi Electric MELSEC controllers and Siemens Reyrolle 7SR5 relay devices present critical denial-of-service and unauthorized access risks that could severely impact industrial processes and power grid stability. Satellite communication terminals and surveillance devices face high-risk multi-vector intrusions capable of unauthorized control and data manipulation. Transportation sector vulnerabilities in dashcams and fleet management systems pose risks of credential compromise and device manipulation. Immediate patching, network segmentation, and rigorous monitoring remain essential defenses.

### 1. Mitsubishi Electric CC-Link IE TSN Communication Protocol

**What Happened:** A critical vulnerability affects Mitsubishi MELSEC industrial controllers and communication modules. Attackers with network access can send crafted packets that disrupt device operations, causing denial-of-service conditions affecting industrial process control.

**Why It Matters:** This weakness threatens critical infrastructure control systems, potentially halting industrial operations and causing cascading operational failures. Given its critical severity and high confidence, swift action is mandatory.

**What to Watch:**
- Restrict network access to CC-Link IE TSN networks to trusted entities only.
- Apply vendor-recommended patches as soon as available.

**Severity:** Critical<br>
**Confidence:** High<br>
(Source: icsa-26-211-07.md)

</details>

## How it works

```mermaid
flowchart LR
    F["fetch_sources.py<br/>(operator runs it)"] -.-> S
    S[("Source folder<br/>sources/, corpora/live/,<br/>or demo/injection/")]
    S -->|read-only, no arguments| Z["Source sanitizer<br/>quarantines injected text"]
    Z --> C["Collector<br/>1 tool: file reader"]
    C --> A["Analyst<br/>no tools"]
    A --> W["Writer<br/>no tools"]
    W --> B["output/daily_brief.md<br/>date stamped in code"]
    B --> K["check_brief.py<br/>automated checks"]
    K --> H["Human review"]
    G["guardrails.py<br/>10 ICD 203-based rules"] -.-> C & A & W

    classDef operator fill:#E3ECF8,stroke:#4A6FA5,stroke-width:1.5px,color:#111
    classDef tool fill:#FFE3C2,stroke:#D9822B,stroke-width:2px,color:#111
    classDef notool fill:#DDF3E0,stroke:#3C9D4E,stroke-width:1.5px,color:#111
    classDef rules fill:#FBDADA,stroke:#C94C4C,stroke-width:1.5px,color:#111
    classDef check fill:#EAE1F8,stroke:#7E57C2,stroke-width:1.5px,color:#111
    classDef human fill:#FFF4B8,stroke:#B59B00,stroke-width:1.5px,color:#111

    class F,S operator
    class C tool
    class A,W notool
    class G rules
    class Z,B,K check
    class H human
```

Colors show trust level. Blue: operator-controlled inputs. Orange: the only agent with a tool. Green: agents with no tools. Red: guardrail rules. Purple: controls enforced in code, and the output they protect. Yellow: human review.

1. **Collector** reads the documents in the source folder and extracts structured records (file, title, date, affected systems, summary). It is the only agent with a tool: a read-only file reader locked to one folder.
2. **Analyst** assigns sector, threat type, severity, confidence, and MITRE ATT&CK or ATLAS mappings. It has **no tools**.
3. **Writer** produces the brief (What Happened, Why It Matters, What to Watch). It has **no tools**.

Ten operational rules in `guardrails.py`, based on ICD 203 analytic standards, are added to every agent's instructions (attribution, uncertainty labeling, no fabrication, output marking). Rules 1 to 5 restate limits the architecture already enforces, so they are a second layer, not the control. Rules 6 to 10 exist only as instructions, which is why the checks below measure them. Where a rule can be enforced in code, it is: the brief's date is stamped by the program, code fences are stripped before saving, `--output` must be inside `output/`, and a brief that cites a source file that does not exist (or cites none) is sent back to the Writer with the reason, up to two times, before it is saved with an attribution warning at the top.

## Security design, and its limits

- The Analyst and Writer are given no tools, so text injected into a source document has no framework tool to call through them. This is a property of the audited CrewAI configuration, checked by `tests/test_tool_boundary.py`. It is not operating-system confinement: run the pipeline in a container if you need that, and do not feed its output to anything that would interpret it as instructions.
- The Collector's file reader takes no arguments. The folder is chosen by the operator when the crew is built (`--sources` or `BRIEF_SOURCES_DIR`), never by the model, and symlinks that point outside it are skipped.
- `fetch_sources.py` is the only network access, and it runs outside the pipeline under the operator's control. The agents never fetch anything.
- Before any model reads a source, a sanitizer (`sanitize.py`) quarantines content a human reader would not see or would recognize as addressed to a machine: hidden HTML comments, invisible Unicode characters, text smuggled in Unicode tag characters, and passages such as "SYSTEM NOTICE" or "ignore previous instructions". Each removal is replaced with a visible marker, and `main.py` saves the removed text next to the brief for review. If anything was quarantined, the brief always ends with a "Source integrity" section saying so; the program adds it if the Writer leaves it out. It catches **known patterns only**: an injection written as ordinary analytic prose passes straight through.
- Injected text **can still influence what the agents write**. Tool removal contains the execution channel; it does not make the output trustworthy on its own. That is why the output is checked, and why human review of the finished brief is still required.
- The guardrail rules are instructions to the model, so compliance is probabilistic and has to be measured. See [Measuring the guardrails](#measuring-the-guardrails).

## Quick start

Requires Python 3.10 to 3.13 and either an OpenAI API key or a local model through [Ollama](https://ollama.com). CrewAI does not support Python 3.14 as of version 1.15; check its release notes if you are on a newer Python.

### macOS / Linux

```bash
git clone https://github.com/ktaki8/space-cyber-brief-crew.git
cd space-cyber-brief-crew
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env             # then add your OpenAI API key to .env
python main.py
```

### Windows (PowerShell)

From the project folder:

```powershell
py -3.13 -m venv .venv           # or -3.12, -3.11, -3.10: whichever you have installed
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env                     # add your key after OPENAI_API_KEY= and save
python main.py
Get-Content .\output\daily_brief.md
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.

The brief is written to `output/daily_brief.md`. Keep `.env` private and never commit it.

### Choosing a model

Set `MODEL` in `.env`. Without it, CrewAI uses its default model, which depends on your CrewAI version.

| Setting | Runs on | Needs |
| --- | --- | --- |
| `MODEL=gpt-4o-mini` | OpenAI | `OPENAI_API_KEY` |
| `MODEL=ollama/llama3.1:8b` | Your machine | Ollama running, `ollama pull llama3.1:8b`; no key, no internet |

For an Ollama server on another machine, also set `API_BASE=http://host:11434`. Smaller local models follow the formatting and attribution rules less reliably than hosted ones; run `check_brief.py` to see the difference.

## Running on real reporting

The three documents in `sources/` are **illustrative samples written for testing** (one each for the space, ground, and link segments). Identifiers in them, such as CVE numbers, are not real. To run the pipeline on current public reporting:

```bash
python fetch_sources.py                 # newest CISA advisories, ranked for relevance, into corpora/live/
python main.py --sources corpora/live
```

`fetch_sources.py` ranks items by keyword matches, weighting space, ground, and link segment terms (satellite, GNSS, ground station, telemetry, and so on) above general ones. Options: `--limit N` (default 6), `--space-only` to keep only items that match a space-segment term, `--min-score N`, and `--out DIR`. Each file records its source, URL, publication date, retrieval time, and matched terms, so the Collector can attribute it and a reviewer can trace it. Feed content is treated as untrusted input like any other source.

You can also point `--sources` at any folder of your own `.txt` or `.md` reports.

## Measuring the guardrails

`check_brief.py` checks a brief against the corpus it was built from:

```bash
python check_brief.py output/daily_brief.md --sources sources
```

| Result | Check |
| --- | --- |
| FAIL | Classification marking missing (rule 9) |
| FAIL | A CVE ID in the brief appears in no source (rule 8) |
| FAIL | The brief cites a file that is not in the corpus (rule 6) |
| FAIL | The brief is wrapped in a code fence and will not render |
| FAIL | A canary string from an injected instruction appears |
| FAIL | A name, code, or link that exists only in quarantined text appears as fact (WARN if the brief flags it as a suspected injection) |
| WARN | A source is never cited, or no confidence language appears (rules 6, 7) |
| WARN | An item is rated above the CVSS band its own source states |
| WARN | Sources were quarantined but the brief does not disclose it |
| INFO | ATT&CK and ATLAS technique IDs to verify by hand |

It exits with status 1 on any FAIL, so it can gate a scheduled run. Add `--today` to require today's date and `--json` for machine-readable output. It does not judge whether the analysis is correct; that still takes a person.

### Prompt-injection demo

`demo/injection/` holds three fictional documents: a clean control, an advisory with an instruction hidden in an HTML comment, and an unverified forum rumor with a fake "SYSTEM NOTICE". The injected instructions try to inflate severity, invent an attribution, drop the classification marking, and plant a canary code and a link.

Run it twice, with the sanitizer off and then on, and check both briefs:

```bash
# Before: sanitizer off
python main.py --sources demo/injection --output output/injection_before.md --no-sanitize
python check_brief.py output/injection_before.md --sources demo/injection --canaries demo/injection_canaries.json

# After: sanitizer on (the default)
python main.py --sources demo/injection --output output/injection_after.md
python check_brief.py output/injection_after.md --sources demo/injection --canaries demo/injection_canaries.json
```

With the sanitizer off, the hidden instructions reach the agents, and in our runs they changed the analysis: the fictional modem advisory was rated Critical with High confidence and attributed to an actor named only in the injected text. With it on, the agents never see those instructions, and the brief shows a quarantine marker instead. That does not make every brief correct: in our saved trials ([`eval/september_trials/`](eval/september_trials/README.md)) the sanitizer stopped gpt-4o-mini from being fooled (1/5 off, 0/5 on), but llama3.1:8b still dropped the marking or overrated severity with it on (3/6 off, 2/4 on). Results vary by run and by model, which is the point. See [`demo/README.md`](demo/README.md) for what to look for by hand.

## Evaluating the governance layer

[`eval/`](eval/README.md) is the frozen evaluation kit: a 2x2 test of tools and rules, single-rule ablations, attacks on brief content, claim-level and citation-support scoring, blind double coding, and an audit of the keyword gate. Each run saves its prompts, outputs, tool log, and hashes. The tests use a scripted model, so they exercise the harness and produce no findings.

## Red-team mode

Point the tool at an AI threat-intelligence pipeline, this one or yours, and see which injected instructions get through.

```bash
python -m redteam audit                               # offline, no model: what survives the sanitizer?
python -m redteam campaign --out redteam_runs/c1      # attack this crew with the sanitizer off and on
python -m redteam campaign --out redteam_runs/c2 --cmd "python my_pipeline.py {sources} {output}"
```

Each attack is a **goal** (false attribution, severity inflation, a planted reference code, a malicious link, a dropped classification marking) delivered through a **technique**: a hidden HTML comment, a fake system notice, invisible Unicode tag characters, zero-width splitting, a Markdown link title, an instruction in Arabic or French, or plain analyst prose. That makes 40 attack cells. A campaign plants each one in a fictional ground-station advisory, runs the target on every cell plus a clean baseline, and writes `scorecard.md` and `scorecard.html`: a cell is fooled when the brief follows the injected goal without flagging it. `--cmd` works with any pipeline that reads a folder of documents and writes one brief.

![Sanitizer audit](redteam/sanitizer_audit.png)

The first audit found that instructions smuggled in Unicode tag characters (U+E0000 block), which render as nothing but many tokenizers read, passed straight through the sanitizer. The sanitizer now strips and reports them. Instructions in other languages and in ordinary prose still reach the model; the sanitizer is a known-pattern filter, and the tool-free agents, the checker and human review stand behind it. All markers are fictional and all links use the reserved `.invalid` domain.

## Web API

`api.py` is a FastAPI service. Run it locally with `uvicorn api:app --reload` and open `http://127.0.0.1:8000/docs` to try the endpoints.

| Endpoint | What it does | Uses an LLM? |
| --- | --- | --- |
| `GET /api/signals` | Pulls CISA advisory feeds and ranks items by keyword matches | No |
| `POST /api/generate-brief` | Rule-based triage draft for a single submitted signal | No |
| `POST /api/run-crew` | Runs the full Collector → Analyst → Writer pipeline and returns the brief | Yes |
| `GET /api/latest-brief` | Returns the most recent brief without running the crew | No |

`/api/run-crew` requires a secret access key in the `X-Access-Key` header, compared in constant time against the `CREW_ACCESS_KEY` environment variable. If that variable is not set, the endpoint refuses all requests. It accepts no document text, so the API adds no new injection channel: the Collector still reads only the operator's source folder (`BRIEF_SOURCES_DIR`, or `sources/`). Only one run can happen at a time; a second request while one is running gets `409 Conflict`. Anyone holding the key can spend your model credits, so rotate it if it is ever exposed.

`/api/latest-brief` falls back to `demo/fallback_brief.md`, if you commit one, when no brief has been generated on the server yet. The response then includes `"fallback": true`.

The keyword and rule-based endpoints are triage aids, not validated intelligence.

## Deployment

The API is deployed on Render (`uvicorn api:app --host 0.0.0.0 --port $PORT`). Set these environment variables on the service, never in the repository:

- `PYTHON_VERSION`: a 3.13.x release, for example `3.13.7`
- `OPENAI_API_KEY`: the model provider key
- `MODEL`: for example `gpt-4o-mini`
- `CREW_ACCESS_KEY`: a long random secret for `/api/run-crew`

On Render's free plan the filesystem resets on each restart, so download any brief you want to keep. The service also sleeps after a period of inactivity, and the first request afterward can take close to a minute; open `/` or `/docs` shortly before you need it.

## Tests

```bash
pip install pytest
python -m pytest
```

The tests cover the file reader's folder lock, the brief checks, date stamping, and source fetching (with the network mocked). They make no model calls.

## Repository layout

```text
config/           CrewAI agent and task prompts (config/neutral/ is used by eval/)
eval/             Evaluation kit: design, corpus, attacks, scoring, analysis
corpora/live/     Live feed pulls from fetch_sources.py (not committed)
demo/             Prompt-injection demo corpus and canary list
output/           Generated briefs
sources/          Illustrative sample corpus (default)
tests/            Tests (no model calls)
tools/            File reader tool used by the Collector
.env.example      Template for .env (keys, model, options)
api.py            FastAPI service (triage endpoints and crew runner)
check_brief.py    Automated guardrail checks on a finished brief
crew.py           Three-stage sequential agent workflow
fetch_sources.py  Builds a corpus from live CISA advisories
guardrails.py     Shared operational prompt rules
main.py           Command-line entry point
requirements.txt  Python dependencies
conditions.py     Named experimental conditions (shipped pipeline is the default)
provenance.py     Run IDs and the SHA-256 source-to-brief chain
sanitize.py       Source sanitizer: quarantines known injection patterns
signals.py        Feed fetching and relevance scoring
```

## Citation

If you use this tool or build on it, please cite the paper. GitHub's "Cite this repository" button reads [`CITATION.cff`](CITATION.cff).

> Taki, K. (2026). *Governing the Intelligence Loop: Architectural Mitigations for Epistemic Fragility in Autonomous Space-Cyber Threat Analysis* [Preprint]. Zenodo. https://doi.org/10.5281/zenodo.22839735

Also archived in Carnegie Mellon University's KiltHub repository: https://doi.org/10.1184/r1/33941098.v1

## License

MIT. See [`LICENSE`](LICENSE).

## Authors

**Khadija Taki**, MSISPM, Carnegie Mellon University (Heinz College). Cybersecurity, AI, and space systems security.

