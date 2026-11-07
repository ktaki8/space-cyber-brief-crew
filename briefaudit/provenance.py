"""Claim-level provenance: which source passage supports each claim?

A brief mixes two kinds of statements, the way ICD 203 separates them:

  - reporting ("What Happened", summaries): facts that should be traceable to
    a source passage;
  - assessment ("Why It Matters", "What to Watch", recommendations): the
    analyst's judgment, which is not expected to appear in the sources.

For every reporting sentence, this module finds the best-matching passage in
the sources the item cites (or in all sources when it cites none) and scores
how much of the sentence that passage supports. For every sentence of either
kind, it checks the specifics a reader would act on: numbers, CVE and
advisory IDs, versions, and multi-word names. A specific that appears in no
source is the strongest sign of fabrication, so it decides the label even
when the wording overlaps.

The method is lexical and deterministic: no model is involved, so the result
is the same every run and can be explained line by line. It measures
support, not truth. A sentence can be supported by a source that is itself
wrong, and paraphrase with no shared words can score low. Treat "partial"
and "unsupported" as review flags, not verdicts.
"""
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field, asdict

STOP = set("""a an and are as at be been being but by can could did do does for from had has have
how if in into is it its may might more most no not of on or our out over per should so some such
than that the their them then there these they this those through to under up was we were what when
where which while who will with within would also any all each other only very via about after
against before between both during further here just own same too again across""".split())

ASSESSMENT_HEADINGS = re.compile(r"why it matters|what to watch|recommend|implication|assessment|"
                                 r"outlook|mitigation|action|next steps|analyst comment|closing|notes?\b|"
                                 r"watch ?list|bottom line|conclusion", re.I)
REPORTING_HEADINGS = re.compile(r"what happened|details|background|key findings|description|incident", re.I)
SUMMARY_HEADINGS = re.compile(r"executive summary|summary|overview|key judg|highlights", re.I)
SUB_HEADINGS = re.compile(ASSESSMENT_HEADINGS.pattern + "|" + REPORTING_HEADINGS.pattern, re.I)
META_LINE = re.compile(r"^\s*(\*\*[^*]+:\*\*|\(source|source:|>|---|\||classification|date:|\*end)", re.I)
ABSENCE = re.compile(r"^(no|none|there (is|are|has been|have been) no|not yet)\b|\b(has|have|had) not been "
                     r"(observed|reported|seen|confirmed)|\bno (known|public|active|reported|confirmed)\b", re.I)
META_SENTENCE = re.compile(r"\b(this|today'?s|the following|the present)\s+(brief|briefing|report|summary)\b|"
                           r"\beach (threat|item) (is|has been) assessed\b", re.I)

WORD = re.compile(r"[A-Za-z][A-Za-z0-9\-']+|\d+(?:\.\d+)*")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ADVISORY = re.compile(r"\b(?:ICSA|ICSMA)-\d{2}-\d{3}-\d{2}[A-Z]?\b|\bAA\d{2}-\d{3}[A-Z]?\b", re.I)
VERSION = re.compile(r"\b(?:v|version\s+)?\d+\.\d+(?:\.\d+)+\b|\bv\d+\.\d+\b", re.I)
NUMBER = re.compile(r"(?<![\w.])\d{1,3}(?:,\d{3})+(?![\w.])|(?<![\w.\-])\d+(?:\.\d+)?\s?(?:%|percent)"
                    r"|(?<![\w.\-])\d{2,}(?![\w.\-:/])")
NAME = re.compile(r"\b[A-Z][a-zA-Z0-9]+(?:[ \-][A-Z][a-zA-Z0-9]+)+\b")
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def split_sentences(text):
    return [s.strip() for s in SENT_SPLIT.split(text) if s.strip()]

# Capitalized phrases that are structure, not claims about the world.
NAME_IGNORE = re.compile(r"^(What Happened|Why It Matters|What to Watch|Executive Summary|Source Integrity|"
                         r"High|Medium|Low|Critical|Moderate|Severity|Confidence|MITRE ATT|ATT&CK)", re.I)


def _stem(w):
    w = w.lower()
    for suf in ("ization", "ations", "ation", "ments", "ment", "ities", "ity", "ings", "ing",
                "ies", "ied", "ers", "er", "ed", "es", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def tokens(text):
    return [_stem(w) for w in WORD.findall(text) if w.lower() not in STOP and len(w) > 1]


def specifics(sentence):
    """Concrete details a reader would act on: IDs, versions, numbers, names."""
    found = {}
    for m in CVE.findall(sentence):
        found[m.upper()] = "cve"
    for m in ADVISORY.findall(sentence):
        found[m.upper()] = "advisory"
    for m in VERSION.findall(sentence):
        found[m.lower().replace("version ", "").lstrip("v")] = "version"
    stripped = CVE.sub(" ", ADVISORY.sub(" ", VERSION.sub(" ", sentence)))
    for m in NUMBER.findall(stripped):
        n = m.replace(" ", "").replace("percent", "%")
        if re.fullmatch(r"(19|20)\d\d", n):        # bare years are rarely the claim
            continue
        found[n] = "number"
    for m in NAME.findall(sentence):
        if not NAME_IGNORE.match(m) and len(m) > 4:
            found[m] = "name"
    return found


def _norm(s):
    return re.sub(r"[\s,]+", " ", s.lower()).strip()


def _name_tokens(spec):
    return [w.lower().rstrip("s") for w in re.split(r"[ \-]", spec) if len(w) > 2]


def specific_in(spec, kind, source_text_norm):
    s = _norm(spec)
    if kind == "name":
        # Every word of the name must appear in the source (plurals folded).
        # A fabricated actor such as "Crimson Meridian" fails; "Siemens PLCs"
        # against "Siemens ... (PLCs)" passes.
        return all(t in source_text_norm for t in _name_tokens(spec))
    if kind == "number":
        s = s.replace(" ", "")
        return s in source_text_norm.replace(" ", "") or s.rstrip("%") + " percent" in source_text_norm
    return s in source_text_norm


@dataclass
class Passage:
    source: str
    text: str
    toks: list = field(default_factory=list)


def passages(corpus, window=2):
    """Split each source into overlapping windows of `window` sentences."""
    out = []
    for name, text in corpus.items():
        body = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
        sents = [s for line in body.splitlines() if line.strip()
                 for s in split_sentences(line) if len(s.split()) >= 3]
        for i in range(len(sents)):
            chunk = " ".join(sents[i:i + window])
            out.append(Passage(name, chunk, tokens(chunk)))
    return out


@dataclass
class Claim:
    text: str
    kind: str                 # "reporting" or "assessment"
    section: str
    label: str = ""           # supported | partial | unsupported | absence | judgment | judgment-unsupported
    score: float = 0.0
    source: str = ""
    evidence: str = ""
    missing: list = field(default_factory=list)   # specifics found in no source

    def as_dict(self):
        return asdict(self)


def parse_items(brief):
    """[(item heading, [(sub-heading, line), ...], item text)].

    An item is a level-2 or level-3 heading that is not itself a standard
    sub-heading such as "What Happened" or "Why It Matters"."""
    items, cur = [], ["brief", [], []]
    sub = ""
    for raw in brief.splitlines():
        line = raw.strip()
        cur[2].append(raw)
        if not line:
            continue
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            if SUB_HEADINGS.fullmatch(heading.strip(": ")) or (SUB_HEADINGS.match(heading) and len(heading) < 30):
                sub = heading
            elif line.startswith(("## ", "### ")):
                items.append(cur)
                cur, sub = [heading, [], [raw]], ""
            continue
        lab = re.match(r"^\*\*([^*]{2,40}?):?\*\*:?\s*(.*)$", line)
        if lab and SUB_HEADINGS.search(lab.group(1)):
            sub, line = lab.group(1), lab.group(2).strip()
            if not line:
                continue
        elif META_LINE.match(line):
            continue
        cur[1].append((sub, line))
    items.append(cur)
    return [(h, lines, "\n".join(txt)) for h, lines, txt in items if lines or h != "brief"]


def _kind(item, sub):
    if sub:
        if ASSESSMENT_HEADINGS.search(sub):
            return "assessment"
        if REPORTING_HEADINGS.search(sub):
            return "reporting"
    if SUMMARY_HEADINGS.search(item) or item == "brief":
        return "summary"
    if ASSESSMENT_HEADINGS.search(item):
        return "assessment"
    return "reporting"


def extract_claims(brief):
    claims = []
    for item, lines, _ in parse_items(brief):
        for sub, block in lines:
            text = re.sub(r"^[-*\u2022]\s+", "", block)
            text = re.sub(r"\*\*|`|\[|\]\([^)]*\)", "", text)
            text = re.sub(r"\((?:source|sources)?:?\s*[\w.\-, ]+\.(?:md|txt)\)", "", text, flags=re.I)
            for s in split_sentences(text):
                if len(s.split()) >= 6 and not META_SENTENCE.search(s):
                    claims.append(Claim(s, _kind(item, sub), item))
    return claims


def _cited(item_text, corpus):
    low = item_text.lower()
    return [n for n in corpus if n.lower() in low or os.path.splitext(n)[0].lower() in low]


def analyze(brief, corpus, supported_at=0.5, partial_at=0.3):
    """Return (claims, summary). corpus is {file name: raw text}.

    Support is measured against the sanitized sources: text the sanitizer
    quarantines as a suspected injection never counts as evidence."""
    from .sanitizer import sanitize_text
    clean = {name: sanitize_text(text).text for name, text in corpus.items()}
    claims = extract_claims(brief)
    pas = passages(clean)
    df = Counter()
    for p in pas:
        df.update(set(p.toks))
    n = max(len(pas), 1)
    idf = {t: math.log(1 + n / (1 + c)) for t, c in df.items()}
    default_idf = math.log(1 + n)
    norms = {name: _norm(t) for name, t in clean.items()}
    all_norm = " ".join(norms.values())
    item_sources = {h: _cited(txt, corpus) for h, _, txt in parse_items(brief)}

    for cl in claims:
        cited = item_sources.get(cl.section, [])
        pool = [p for p in pas if p.source in cited] or pas
        scope_norm = " ".join(norms[s] for s in cited) if cited else all_norm

        spec = specifics(cl.text)
        cl.missing = [s for s, k in spec.items() if not specific_in(s, k, all_norm)]
        not_in_cited = [s for s, k in spec.items() if cited and s not in cl.missing
                        and not specific_in(s, k, scope_norm)]

        ct = set(tokens(cl.text))
        w = lambda ts: sum(idf.get(t, default_idf) for t in ts)
        weight = w(ct) or 1.0
        scored = sorted(((w(ct & set(p.toks)) / weight, i, p) for i, p in enumerate(pool)
                         if ct & set(p.toks)), key=lambda x: (-x[0], x[1]))
        best, best_p = (scored[0][0], scored[0][2]) if scored else (0.0, None)
        if best_p:
            # A claim may combine two statements from the same source.
            rest = ct - set(best_p.toks)
            second = max((w(rest & set(p.toks)) / weight for _, _, p in scored[1:6]
                          if p.source == best_p.source), default=0.0)
            best += second
        cl.score = round(min(best, 1.0), 2)
        if best_p:
            cl.source, cl.evidence = best_p.source, best_p.text[:400]

        if cl.kind in ("assessment", "summary"):
            cl.label = "judgment-unsupported" if cl.missing else "judgment"
        elif cl.missing:
            cl.label = "unsupported"
        elif best < supported_at and ABSENCE.search(cl.text):
            # "No exploitation has been reported" can be true by omission;
            # the source does not say it, so a person has to confirm it.
            cl.label = "absence"
        elif best < partial_at:
            cl.label = "unsupported"
        elif best >= supported_at and not not_in_cited:
            cl.label = "supported"
        else:
            cl.label = "partial"

    counts = Counter(c.label for c in claims)
    reporting = [c for c in claims if c.kind == "reporting"]
    summary = {
        "claims": len(claims),
        "reporting": len(reporting),
        "judgment": len(claims) - len(reporting),
        "supported": counts["supported"],
        "partial": counts["partial"],
        "unsupported": counts["unsupported"],
        "absence_claims": counts["absence"],
        "judgment_with_unsourced_specifics": counts["judgment-unsupported"],
        "support_rate": round(counts["supported"] / len(reporting), 2) if reporting else None,
    }
    return claims, summary
