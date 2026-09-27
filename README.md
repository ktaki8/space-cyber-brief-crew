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

Requires Python 3.10 or newer and an OpenAI API key.

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

## Sample sources

The three documents in `sources/` are **illustrative samples written for testing** (one each for the space, ground, and link segments). Identifiers in them, such as CVE numbers, are not real. Replace them with your own documents to use the pipeline on real reporting.

## Optional: ingestion API

`api.py` is a separate FastAPI prototype that pulls CISA advisory feeds and ranks items by keyword matches. It is not connected to the agent pipeline. Run it with `uvicorn api:app --reload`.

## Author

Khadija Taki, MSISPM, Carnegie Mellon University (Heinz College). Co-author of the accompanying paper: Brian G. Rodiles Delgado, University of West Florida.
