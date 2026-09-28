from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import secrets
import threading
from datetime import datetime, timezone

from signals import collect_signals

app = FastAPI(title="Space Cyber Crew API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignalInput(BaseModel):
    source: str
    title: str
    summary: str
    link: str | None = ""

@app.get("/")
def root():
    return {"status": "ok", "message": "Space Cyber Crew API is running"}

@app.get("/api/signals")
def get_signals():
    """Newest CISA advisories ranked by keyword relevance (no LLM)."""
    items, errors = collect_signals(per_feed=15)
    results = [
        {
            "source": i["source"],
            "title": i["title"],
            "summary": i["summary"][:300] + ("..." if len(i["summary"]) > 300 else ""),
            "link": i["link"],
            "score": i["score"],
            "matched_terms": i["matched_terms"],
        }
        for i in items
    ]
    filtered = [r for r in results if r["score"] > 0]
    if errors and not results:
        raise HTTPException(status_code=502, detail={"message": "All feeds failed.", "errors": errors})
    return filtered[:8] if filtered else results[:8]


@app.post("/api/generate-brief")
def generate_brief(signal: SignalInput):
    text = f"{signal.title} {signal.summary}".lower()

    if "vendor" in text or "supply chain" in text:
        domain = "Supply Chain / Third-Party Risk"
        priority = "Medium-High"
        action = "Review vendor dependencies, check connected services, and monitor for follow-on indicators."
    elif "authentication" in text or "login" in text or "credential" in text:
        domain = "Mission Support Systems"
        priority = "Medium"
        action = "Audit authentication logs, review failed access patterns, and verify privileged account controls."
    elif "scanning" in text or "exposed" in text or "network" in text:
        domain = "Ground Station / Communications Layer"
        priority = "Medium-High"
        action = "Review exposed services, validate access controls, and monitor for reconnaissance or enumeration activity."
    elif "vulnerability" in text or "advisory" in text:
        domain = "Space-Adjacent Infrastructure"
        priority = "Medium"
        action = "Assess exposure, map affected systems, and prioritize remediation based on operational relevance."
    else:
        domain = "Space Communications / Supporting Infrastructure"
        priority = "Medium"
        action = "Validate the signal, correlate with related reporting, and assess whether continued monitoring is warranted."

    brief_title = f"Analyst Review: {signal.title}"

    brief_summary = (
        f"This signal may indicate emerging cyber risk relevant to space-supporting infrastructure, "
        f"communications systems, or operational dependencies. Additional validation and correlation "
        f"would be required to determine operational significance."
    )

    return {
        "title": brief_title,
        "summary": brief_summary,
        "priority": priority,
        "domain": domain,
        "action": action,
        "source": signal.source,
        "link": signal.link
    }


# ---------------------------------------------------------------------------
# Agent pipeline endpoints
#
# These run the real CrewAI pipeline (crew.py) on the documents in sources/.
# The request body does not carry any document text, so the API does not
# open a new prompt-injection channel: the Collector still reads only the
# fixed sources/ folder, exactly as when running main.py locally.
#
# Running the crew costs OpenAI credits, so /api/run-crew requires a secret
# access key sent in the X-Access-Key header. Set CREW_ACCESS_KEY on the
# server. If it is not set, the endpoint refuses every request (fails closed).
# ---------------------------------------------------------------------------

BRIEF_PATH = "output/daily_brief.md"
# A known-good brief committed to the repo. Served when no run has happened
# yet, for example after Render's free plan resets the filesystem.
FALLBACK_BRIEF_PATH = "demo/fallback_brief.md"
_crew_lock = threading.Lock()
_last_run = {"status": "never run", "finished_at": None, "error": None}


def _check_access_key(provided: str | None):
    expected = os.getenv("CREW_ACCESS_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="Crew runs are disabled: CREW_ACCESS_KEY is not set on the server.")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Missing or incorrect access key.")


def _clean_brief(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


@app.post("/api/run-crew")
def run_crew(x_access_key: str | None = Header(default=None)):
    """Run the Collector -> Analyst -> Writer pipeline. Takes 1-5 minutes."""
    _check_access_key(x_access_key)

    if not (os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
        raise HTTPException(status_code=503, detail="No model API key is set on the server (OPENAI_API_KEY).")

    # One run at a time: runs share the output file and cost money.
    if not _crew_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A crew run is already in progress. Try again in a few minutes.")

    try:
        _last_run.update(status="running", error=None)
        os.makedirs("output", exist_ok=True)

        from crew import build_crew  # imported here so the API starts fast
        result = build_crew().kickoff()

        brief = getattr(result, "raw", None) or str(result)
        finished = datetime.now(timezone.utc).isoformat()
        _last_run.update(status="completed", finished_at=finished)
        return {"status": "completed", "finished_at": finished, "brief_markdown": _clean_brief(brief)}
    except HTTPException:
        raise
    except Exception as e:
        _last_run.update(status="failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Crew run failed: {e}")
    finally:
        _crew_lock.release()


@app.get("/api/latest-brief")
def latest_brief():
    """Return the most recent brief without running the crew (free).

    If no brief has been generated on this server, returns the committed
    fallback brief with "fallback": true, so a demo never shows an empty page.
    """
    for path, is_fallback in ((BRIEF_PATH, False), (FALLBACK_BRIEF_PATH, True)):
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                brief = f.read()
            return {"last_run": _last_run, "fallback": is_fallback, "brief_markdown": _clean_brief(brief)}
    raise HTTPException(status_code=404, detail="No brief has been generated yet.")
