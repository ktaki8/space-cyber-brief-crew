"""Public advisory feeds and keyword relevance scoring.

Shared by api.py (the /api/signals triage endpoint) and fetch_sources.py
(which turns feed items into a source corpus for the agent pipeline).

Keyword scoring is a triage aid, not validated intelligence.
"""
import re
import shutil
import subprocess
import urllib.request
from html import unescape

import feedparser

FEEDS = [
    ("CISA Cybersecurity Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("CISA ICS Advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
]

# CISA's bot protection returns 403 unless the request looks like a browser.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)

# Terms that tie an item to the space, ground, or link segments. Weighted higher.
SPACE_TERMS = [
    "satellite", "spacecraft", "space", "ground station", "ground segment",
    "gps", "gnss", "pnt", "positioning", "navigation", "timing",
    "vsat", "telemetry", "uplink", "downlink", "orbit", "antenna",
    "radio", "rf", "sdr", "maritime", "aviation",
]

# General cyber and infrastructure terms. Weighted lower.
GENERAL_TERMS = [
    "critical infrastructure", "infrastructure", "communications", "network",
    "vulnerability", "remote code execution", "authentication", "supply chain",
    "vendor", "scanning", "firmware", "exploit",
]

SPACE_WEIGHT = 3
GENERAL_WEIGHT = 1

_BLOCK_TAGS = re.compile(r"</?(p|div|br|li|ul|ol|h[1-6]|tr|table|section)[^>]*>", re.I)
_ANY_TAG = re.compile(r"<[^>]+>")


def clean_html(text: str, keep_paragraphs: bool = False) -> str:
    """Strip HTML. With keep_paragraphs, block elements become line breaks."""
    if not text:
        return ""
    if keep_paragraphs:
        text = _BLOCK_TAGS.sub("\n", text)
        text = _ANY_TAG.sub("", unescape(text))
        lines = [" ".join(line.split()) for line in text.split("\n")]
        out, blank = [], False
        for line in lines:
            if line:
                out.append(line)
                blank = False
            elif not blank and out:
                out.append("")
                blank = True
        return "\n".join(out).strip()
    text = _ANY_TAG.sub("", unescape(text))
    return " ".join(text.split())


def _term_found(term: str, text: str) -> bool:
    return re.search(r"\b" + re.escape(term) + r"\b", text) is not None


def score_signal(title: str, summary: str) -> tuple[int, list[str]]:
    """Return (score, matched terms). Whole-word matching, case-insensitive."""
    text = f"{title} {summary}".lower()
    matched, score = [], 0
    for term in SPACE_TERMS:
        if _term_found(term, text):
            matched.append(term)
            score += SPACE_WEIGHT
    for term in GENERAL_TERMS:
        if _term_found(term, text):
            matched.append(term)
            score += GENERAL_WEIGHT
    return score, matched


def is_space_relevant(matched_terms: list[str]) -> bool:
    return any(t in SPACE_TERMS for t in matched_terms)


HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
}


def _fetch_with_urllib(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_with_curl(url: str, timeout: int) -> bytes:
    """Fallback. Some bot protection (CISA's included) blocks Python's HTTP
    client even with browser headers but accepts curl, which ships with
    Windows 10+, macOS, and most Linux systems."""
    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("curl is not installed")
    cmd = [curl, "-sSfL", "--max-time", str(timeout), "--compressed"]
    for name, value in HEADERS.items():
        cmd += ["-H", f"{name}: {value}"]
    cmd.append(url)
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace").strip() or f"curl exit {result.returncode}")
    return result.stdout


def fetch_feed(url: str, timeout: int = 20):
    """Fetch and parse one feed. Returns (entries, error_message_or_None).

    Tries Python's HTTP client first, then curl.
    """
    try:
        data = _fetch_with_urllib(url, timeout)
    except Exception as first:  # network errors, 403s, timeouts
        try:
            data = _fetch_with_curl(url, timeout)
        except Exception as second:
            return [], f"{type(first).__name__}: {first}; curl fallback: {second}"
    parsed = feedparser.parse(data)
    if parsed.bozo and not parsed.entries:
        return [], f"Could not parse feed: {parsed.bozo_exception}"
    return parsed.entries, None


def entry_text(entry) -> str:
    """Best available body text for a feed entry, as raw HTML."""
    content = entry.get("content")
    if content and isinstance(content, list) and content[0].get("value"):
        return content[0]["value"]
    return entry.get("summary", "") or entry.get("description", "")


def collect_signals(per_feed: int = 15):
    """Fetch every feed and score its newest items.

    Returns (items, errors). Each item has source, title, summary (plain text),
    body_html, link, published, score, and matched terms.
    """
    items, errors = [], []
    for source_name, url in FEEDS:
        entries, error = fetch_feed(url)
        if error:
            errors.append({"source": source_name, "url": url, "error": error})
            continue
        for entry in entries[:per_feed]:
            title = clean_html(entry.get("title", ""))
            body_html = entry_text(entry)
            summary = clean_html(body_html)
            score, matched = score_signal(title, summary)
            items.append({
                "source": source_name,
                "title": title,
                "summary": summary,
                "body_html": body_html,
                "link": entry.get("link", ""),
                "published": entry.get("published", "") or entry.get("updated", ""),
                "score": score,
                "matched_terms": matched,
            })
    items.sort(key=lambda x: x["score"], reverse=True)
    return items, errors
