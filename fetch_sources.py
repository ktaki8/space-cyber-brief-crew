"""Build a source corpus from live public advisory feeds.

This runs outside the agent pipeline, under the operator's control. The
agents still have no network access: this script writes Markdown files to a
folder, and you then point the crew at that folder.

    python fetch_sources.py                  # writes corpora/live/
    python main.py --sources corpora/live    # runs the crew on it

Feed content is untrusted input. Every file records where it came from so the
Collector can attribute it and a reviewer can check it.
"""
import argparse
import os
import re
import sys
from datetime import datetime, timezone

from signals import FEEDS, clean_html, collect_signals, is_space_relevant

DEFAULT_OUT = os.path.join("corpora", "live")
MAX_BODY_CHARS = 8000


def slugify(text: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len].rstrip("-") or "item"


def file_name_for(item: dict) -> str:
    # Prefer the advisory ID at the end of the URL (for example icsa-26-258-01).
    tail = item["link"].rstrip("/").rsplit("/", 1)[-1] if item["link"] else ""
    base = slugify(tail) if tail else slugify(item["title"])
    return f"{base}.md"


def render(item: dict, retrieved: str) -> str:
    body = clean_html(item["body_html"], keep_paragraphs=True)
    truncated = len(body) > MAX_BODY_CHARS
    if truncated:
        body = body[:MAX_BODY_CHARS].rsplit(" ", 1)[0] + " [...]"
    lines = [
        f"# {item['title']}",
        "",
        f"- **Source:** {item['source']} (public RSS feed)",
        f"- **URL:** {item['link'] or 'not provided'}",
        f"- **Published:** {item['published'] or 'not provided in feed'}",
        f"- **Retrieved:** {retrieved}",
        f"- **Relevance terms:** {', '.join(item['matched_terms']) or 'none'}",
        "- **Provenance:** automated retrieval; not reviewed by an analyst.",
        "",
        "---",
        "",
        body or "(The feed provided no body text for this item.)",
    ]
    if truncated:
        lines += ["", f"(Body truncated at {MAX_BODY_CHARS} characters; see the URL for the full advisory.)"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description="Fetch public advisories into a source corpus.")
    p.add_argument("--out", default=DEFAULT_OUT, help=f"output folder (default: {DEFAULT_OUT})")
    p.add_argument("--limit", type=int, default=6, help="maximum documents to write (default: 6)")
    p.add_argument("--per-feed", type=int, default=30, help="newest items to consider per feed (default: 30)")
    p.add_argument("--min-score", type=int, default=1, help="minimum relevance score (default: 1)")
    p.add_argument("--space-only", action="store_true",
                   help="keep only items that match at least one space/ground/link term")
    p.add_argument("--keep", action="store_true",
                   help="keep existing files in the output folder instead of clearing it")
    args = p.parse_args(argv)

    out = os.path.abspath(args.out)
    if out == os.path.abspath("sources"):
        print("Refusing to write into sources/: keep live data separate from the curated samples.")
        return 2

    print("Fetching feeds:")
    for name, url in FEEDS:
        print(f"  - {name}: {url}")
    items, errors = collect_signals(per_feed=args.per_feed)

    for e in errors:
        print(f"WARNING: {e['source']} failed ({e['error']})")
    if not items:
        print("No items retrieved. Check your network connection, or use the demo corpus offline.")
        return 1

    # CISA often lists the same advisory in more than one feed: keep the first.
    unique, seen = [], set()
    for i in items:
        key = i["link"] or i["title"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(i)

    selected = [i for i in unique if i["score"] >= args.min_score]
    if args.space_only:
        selected = [i for i in selected if is_space_relevant(i["matched_terms"])]
    selected = selected[: args.limit]
    if not selected:
        print("Items were retrieved, but none met the filters. Try a lower --min-score or drop --space-only.")
        return 1

    os.makedirs(out, exist_ok=True)
    if not args.keep:
        # Clear only previously fetched Markdown files, never the folder itself.
        for old in os.listdir(out):
            path = os.path.join(out, old)
            if old.endswith(".md") and os.path.isfile(path) and not os.path.islink(path):
                os.remove(path)

    retrieved = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    used = set(os.listdir(out))
    print(f"\nWriting {len(selected)} document(s) to {os.path.relpath(out)}:")
    for item in selected:
        name = file_name_for(item)
        stem, n = name[:-3], 2
        while name in used:
            name = f"{stem}-{n}.md"
            n += 1
        used.add(name)
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(render(item, retrieved))
        print(f"  [{item['score']:>2}] {name}  {item['title'][:70]}")

    print(f"\nNext: python main.py --sources {os.path.relpath(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
