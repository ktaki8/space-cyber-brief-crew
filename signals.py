"""Public advisory feeds and keyword relevance scoring.

Shared by api.py (the /api/signals triage endpoint) and fetch_sources.py
(which turns feed items into a source corpus for the agent pipeline).

Keyword scoring is a triage aid, not validated intelligence.
"""
import json
import re
import shutil
import subprocess
import urllib.request
from calendar import timegm
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from html import unescape

import feedparser

# Each feed is (display name, URL). The region is part of the name so it shows
# up everywhere the source is displayed. A feed that fails is reported and
# skipped; the others still load.
FEEDS = [
    # United States
    ("CISA Cybersecurity Advisories (US)", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("CISA ICS Advisories (US)", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
    # Europe
    ("NCSC (UK)", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
    ("CERT-FR (France)", "https://www.cert.ssi.gouv.fr/feed/"),
    ("CERT Polska (Poland)", "https://cert.pl/en/atom.xml"),
    # Asia
    ("JPCERT/CC (Japan)", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"),
    ("JVN (Japan)", "https://jvn.jp/en/rss/jvn.rdf"),
]

# CISA's Known Exploited Vulnerabilities catalog, published by CISA on GitHub.
# CISA's own website blocks many cloud servers (such as Render), but GitHub
# does not, so this source keeps the demo on real data when the RSS feeds fail.
KEV_SOURCE = "CISA Known Exploited Vulnerabilities (US)"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# CISA's bot protection returns 403 unless the request looks like a browser.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)

# Items older than this are dropped, so old advisories that a feed re-publishes
# (CERT-FR does this when it revises an advisory) don't show as new.
MAX_AGE_DAYS = 90

# Terms that clearly tie an item to the space, ground, or link segments.
SPACE_TERMS = [
    "satellite", "satellites", "spacecraft", "ground station", "ground segment",
    "gps", "gnss", "pnt", "vsat", "orbit", "orbital", "sdr",
    # French equivalents, for CERT-FR
    "spatial", "station sol", "navigation par satellite",
]

# Terms that are space-related only in context: "navigation" in a phone app or
# "space" in "disk space" are not space threats. These count only when the
# item also contains at least one term from SPACE_TERMS.
CONTEXT_SPACE_TERMS = [
    "space", "positioning", "navigation", "timing", "telemetry",
    "uplink", "downlink", "antenna", "radio", "rf", "maritime", "aviation",
]

# General cyber and infrastructure terms. Weighted lower.
GENERAL_TERMS = [
    "critical infrastructure", "infrastructure", "communications", "network",
    "vulnerability", "remote code execution", "authentication", "supply chain",
    "vendor", "scanning", "firmware", "exploit",
    # French equivalents, for CERT-FR
    "vulnérabilité", "vulnérabilités", "exécution de code arbitraire à distance",
    "contournement de la politique de sécurité", "chaîne d'approvisionnement",
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
    if matched:  # context terms count only alongside a clear space term
        for term in CONTEXT_SPACE_TERMS:
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


_CERTFR_YEAR = re.compile(r"CERTFR-(\d{4})-", re.I)


def entry_datetime(entry):
    """Publication time of a feed entry (UTC), or None if the feed gives none."""
    for key in ("published_parsed", "updated_parsed"):
        value = entry.get(key)
        if value:
            return datetime.fromtimestamp(timegm(value), tz=timezone.utc)
    return None


def is_too_old(published, link: str = "", now=None) -> bool:
    """True if the item is older than MAX_AGE_DAYS.

    Items with no date are kept. CERT-FR advisory IDs carry the year the
    advisory was first issued, which is checked too, because a revision of a
    2019 advisory can carry a 2026 date in the feed.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    if published and published < cutoff:
        return True
    m = _CERTFR_YEAR.search(link or "")
    if m and int(m.group(1)) < cutoff.year:
        return True
    return False


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


def fetch_bytes(url: str, timeout: int = 20) -> bytes:
    """Fetch a URL with Python's HTTP client, falling back to curl."""
    try:
        return _fetch_with_urllib(url, timeout)
    except Exception as first:
        try:
            return _fetch_with_curl(url, timeout)
        except Exception as second:
            raise RuntimeError(f"{type(first).__name__}: {first}; curl fallback: {second}")


def kev_items(data: bytes, limit: int = 15) -> list[dict]:
    """Turn the KEV catalog JSON into signal items, newest additions first."""
    vulns = json.loads(data).get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    items = []
    for v in vulns[:limit]:
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            added = None
        if is_too_old(added):
            continue
        cve = v.get("cveID", "")
        name = v.get("vulnerabilityName", "") or f"{v.get('vendorProject', '')} {v.get('product', '')}"
        title = f"{cve}: {name}" if cve else name
        desc = v.get("shortDescription", "").strip()
        if desc and not desc.endswith("."):
            desc += "."
        parts = [
            desc,
            f"Affected: {v.get('vendorProject', '')} {v.get('product', '')}.",
            f"Added to CISA KEV on {v.get('dateAdded', 'unknown date')}; federal remediation due {v.get('dueDate', 'not stated')}.",
            f"Known ransomware use: {v.get('knownRansomwareCampaignUse', 'Unknown')}.",
            f"Required action: {v.get('requiredAction', '')}",
        ]
        summary = " ".join(p.strip() for p in parts if p and p.strip())
        body_html = "".join(f"<p>{p}</p>" for p in parts if p and p.strip())
        items.append({
            "source": KEV_SOURCE,
            "title": title,
            "summary": summary,
            "body_html": body_html,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            "published": v.get("dateAdded", ""),
        })
    return items


def fetch_feed(url: str, timeout: int = 20):
    """Fetch and parse one feed. Returns (entries, error_message_or_None).

    Tries Python's HTTP client first, then curl.
    """
    try:
        data = fetch_bytes(url, timeout)
    except Exception as e:  # network errors, 403s, timeouts
        return [], str(e)
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


def _interleave_by_source(items: list[dict]) -> list[dict]:
    """Keep the best item from every source near the top.

    Items are ranked by score within each source, then taken round-robin,
    highest-scoring sources first. Without this, one large feed (such as the
    KEV catalog) can fill the whole list and hide the other regions.
    """
    groups: dict[str, list[dict]] = {}
    for item in sorted(items, key=lambda x: x["score"], reverse=True):
        groups.setdefault(item["source"], []).append(item)
    ordered, rank = [], 0
    while any(rank < len(g) for g in groups.values()):
        tier = [g[rank] for g in groups.values() if rank < len(g)]
        ordered.extend(sorted(tier, key=lambda x: x["score"], reverse=True))
        rank += 1
    return ordered


def _feed_items(source_name: str, url: str, per_feed: int):
    entries, error = fetch_feed(url)
    if error:
        return [], {"source": source_name, "url": url, "error": error}
    items = []
    for entry in entries[:per_feed]:
        if is_too_old(entry_datetime(entry), entry.get("link", "")):
            continue
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
    return items, None


def _kev_source_items(per_feed: int):
    try:
        items = kev_items(fetch_bytes(KEV_URL), limit=per_feed)
    except Exception as e:
        return [], {"source": KEV_SOURCE, "url": KEV_URL, "error": str(e)}
    for item in items:
        item["score"], item["matched_terms"] = score_signal(item["title"], item["summary"])
    return items, None


def collect_signals(per_feed: int = 15):
    """Fetch every feed (in parallel) and score its newest items.

    Returns (items, errors). Each item has source, title, summary (plain text),
    body_html, link, published, score, and matched terms. Items are ordered so
    each source's best item appears near the top.
    """
    jobs = [(_feed_items, (name, url, per_feed)) for name, url in FEEDS]
    # KEV catalog via GitHub: works even where cisa.gov blocks the server.
    jobs.append((_kev_source_items, (per_feed,)))

    items, errors = [], []
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(fn, *args) for fn, args in jobs]
        for f in futures:
            got, error = f.result()
            items.extend(got)
            if error:
                errors.append(error)
    return _interleave_by_source(items), errors
