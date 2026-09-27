from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import feedparser
import os
import re
import secrets
import threading
from datetime import datetime, timezone

app = FastAPI(title="Space Cyber Crew API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RSS_FEEDS = [
    ("CISA Advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml"),
    ("CISA Alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
]

KEYWORDS = [
    "satellite",
    "space",
    "ground station",
    "communications",
    "network",
    "infrastructure",
    "critical infrastructure",
    "cyber",
    "vulnerability",
    "scanning",
    "vendor",
    "supply chain",
    "authentication",
]

class SignalInput(BaseModel):
    source: str
    title: str
    summary: str
    link: str | None = ""

def clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    return " ".join(text.split())

def score_signal(title: str, summary: str) -> int:
    text = f"{title} {summary}".lower()
    score = 0
    for keyword in KEYWORDS:
        if keyword in text:
            score += 1
    return score

@app.get("/")
def root():
    return {"status": "ok", "message": "Space Cyber Crew API is running"}

@app.get("/api/signals")
def get_signals():
    results = []

    for source_name, url in RSS_FEEDS:
        feed = feedparser.parse(url)

        for entry in feed.entries[:15]:
            title = clean_html(entry.get("title", ""))
            summary = clean_html(entry.get("summary", "") or entry.get("description", ""))
            link = entry.get("link", "")

            score = score_signal(title, summary)

            results.append({
                "source": source_name,
                "title": title,
                "summary": summary[:300] + ("..." if len(summary) > 300 else ""),
                "link": link,
                "score": score
            })

    # Sort by relevance score, then keep top results
    results = sorted(results, key=lambda x: x["score"], reverse=True)

    # Remove very weak items if possible
    filtered = [item for item in results if item["score"] > 0]

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
    """Return the most recent brief without running the crew (free)."""
    if not os.path.isfile(BRIEF_PATH):
        raise HTTPException(status_code=404, detail="No brief has been generated yet.")
    with open(BRIEF_PATH, "r", encoding="utf-8") as f:
        brief = f.read()
    return {"last_run": _last_run, "brief_markdown": _clean_brief(brief)}
