# Space-Cyber Brief Crew

A governed multi-agent pipeline, built with CrewAI, that turns a folder of space-domain cyber threat documents into a structured intelligence brief. It accompanies the paper *Governing the Intelligence Loop: Architectural Mitigations for Epistemic Fragility in Autonomous Space-Cyber Threat Analysis* (Taki and Rodiles Delgado).

## How it works

Three agents run in sequence:

1. **Collector** reads the documents in `sources/` and extracts structured records (file, title, date, affected systems, summary). It is the only agent with a tool: a read-only file reader locked to the `sources/` folder.
2. **Analyst** assigns sector, threat type, severity, confidence, and MITRE ATT&CK or ATLAS mappings. It has **no tools**.
3. **Writer** produces the brief (What Happened, Why It Matters, What to Watch). It has **no tools**.

Ten operational rules in `guardrails.py`, based on ICD 203 analytic standards, are added to every agent's instructions (attribution, uncertainty labeling, no fabrication, output marking).

## Security design, and its limits

- The Analyst and Writer have no tools, so text injected into a source document cannot make them run commands, read files, or access the network.
- The Collector's file reader takes no arguments. Its folder is fixed in code, and symlinks that point outside `sources/` are skipped.
- Injected text **can still influence what the agents write**. Tool removal contains the execution channel; it does not make the output trustworthy on its own. Human review of the finished brief is still required.
- The guardrail rules are instructions to the model, so compliance is probabilistic and has to be measured.

## Quick start

Requires Python 3.10 to 3.13 (CrewAI does not yet support 3.14) and an OpenAI API key.

```bash
git clone https://github.com/ktaki8/space-cyber-brief-crew.git
cd space-cyber-brief-crew
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then add your OpenAI API key to .env
python main.py
```

The brief is written to `output/daily_brief.md`.

**Model:** unless you set `MODEL` in `.env` (for example `MODEL=gpt-4o-mini`), CrewAI uses its default model, which depends on your CrewAI version.

Keep `.env` private and never commit it. The pipeline checks for either `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

### Windows (PowerShell)

From the project folder:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env                     # add your key after OPENAI_API_KEY= and save
python main.py
Get-Content .\output\daily_brief.md
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.

## Sample sources

The three documents in `sources/` are **illustrative samples written for testing** (one each for the space, ground, and link segments). Identifiers in them, such as CVE numbers, are not real. Replace them with your own documents to use the pipeline on real reporting.

## Web API

`api.py` is a FastAPI service. Run it locally with `uvicorn api:app --reload` and open `http://127.0.0.1:8000/docs` to try the endpoints.

| Endpoint | What it does | Uses an LLM? |
| --- | --- | --- |
| `GET /api/signals` | Pulls CISA advisory feeds and ranks items by keyword matches | No |
| `POST /api/generate-brief` | Rule-based triage draft for a single submitted signal | No |
| `POST /api/run-crew` | Runs the full Collector → Analyst → Writer pipeline on `sources/` and returns the brief | Yes |
| `GET /api/latest-brief` | Returns the most recent brief without running the crew | No |

`/api/run-crew` requires a secret access key in the `X-Access-Key` header, matched against the `CREW_ACCESS_KEY` environment variable. If that variable is not set, the endpoint refuses all requests. It accepts no document text, so the API adds no new injection channel: the Collector still reads only the fixed `sources/` folder. Only one run can happen at a time.

The keyword and rule-based endpoints are triage aids, not validated intelligence.

## Deployment

The API is deployed on Render (`uvicorn api:app --host 0.0.0.0 --port $PORT`). Set these environment variables on the service, never in the repository:

- `PYTHON_VERSION`: a 3.13.x release, for example `3.13.7`
- `OPENAI_API_KEY`: the model provider key
- `MODEL`: for example `gpt-4o-mini`
- `CREW_ACCESS_KEY`: a long random secret for `/api/run-crew`

On Render's free plan the filesystem resets on each restart, so download any brief you want to keep.

## Repository layout

```text
config/        CrewAI agent and task prompts
output/        Generated brief output
sources/       Approved local text/Markdown source corpus
tools/         File reader tool used by the Collector
api.py         FastAPI service (triage endpoints and crew runner)
crew.py        Three-stage sequential agent workflow
guardrails.py  Shared operational prompt rules
main.py        Local workflow entry point
```

## Authors

**Khadija Taki**, MSISPM, Carnegie Mellon University (Heinz College). Cybersecurity, AI, and space systems security.

