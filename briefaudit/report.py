"""HTML and SARIF output for an audit.

render_html() returns one self-contained page (no external files), so the
report can be emailed, attached to a ticket, or opened offline at a booth.
"""
import html
import json
import re

from .sanitizer import sanitize_text

LABELS = {
    "supported": ("Supported", "A cited source passage supports this claim."),
    "partial": ("Partial", "A source passage supports part of this claim. Check the rest."),
    "unsupported": ("Unsupported", "No source passage supports this claim, or it contains a detail found in no source."),
    "absence": ("Absence claim", "Says something was not reported. The sources do not say so; confirm by hand."),
    "judgment": ("Judgment", "Analyst assessment. Not expected in the sources; checked for unsourced details only."),
    "judgment-unsupported": ("Judgment with unsourced detail", "An assessment that relies on a detail found in no source."),
}

CSS = """
:root{--ink:#17212B;--muted:#5B6875;--line:#DCE2E8;--bg:#F6F8FA;--card:#FFFFFF;
--ok:#1B7F4B;--okbg:#E3F4EA;--part:#9A6200;--partbg:#FFF1D6;--bad:#B3261E;--badbg:#FCE4E2;
--abs:#6B3FA0;--absbg:#EFE6FA;--jud:#4D5B69;--judbg:#EEF1F4;--accent:#0F4C81}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--ink:#E6EBF0;--muted:#A3AFBC;--line:#2C3743;
--bg:#11181F;--card:#18212A;--okbg:#14301F;--partbg:#3A2C10;--badbg:#3D1715;--absbg:#2A1D3D;--judbg:#222C36;
--ok:#6DD39A;--part:#F2B84B;--bad:#FF8A80;--abs:#C9A6F5;--jud:#B6C2CE;--accent:#7FB6E8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line);padding:20px 24px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}
.sub{color:var(--muted);font-size:13px}.wrap{max-width:1180px;margin:0 auto;padding:20px 16px}
.verdict{display:inline-block;font-weight:700;padding:3px 10px;border-radius:4px;margin-right:8px}
.v-fail{background:var(--badbg);color:var(--bad)}.v-pass{background:var(--okbg);color:var(--ok)}
.tally{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.tally span{font-size:13px;padding:2px 9px;border-radius:12px;border:1px solid var(--line)}
.grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:20px}
@media (max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:18px}
.brief h3,.brief h4{margin:18px 0 6px;font-size:15px}.brief p,.brief li{margin:4px 0}
.c{border-radius:3px;padding:1px 2px;cursor:pointer;border-bottom:2px solid transparent}
.c:focus{outline:2px solid var(--accent);outline-offset:1px}
.c-supported{background:var(--okbg);border-color:var(--ok)}
.c-partial{background:var(--partbg);border-color:var(--part)}
.c-unsupported{background:var(--badbg);border-color:var(--bad)}
.c-absence{background:var(--absbg);border-color:var(--abs);border-bottom-style:dashed}
.c-judgment{background:transparent;border-color:var(--line)}
.c-judgment-unsupported{background:var(--badbg);border-color:var(--bad);border-bottom-style:dotted}
.c.active{outline:2px solid var(--accent)}
#detail{position:sticky;top:12px}#detail .lab{font-weight:700}
#detail blockquote{margin:10px 0;padding:10px 12px;background:var(--bg);border-left:3px solid var(--accent);
font-size:14px}.miss{color:var(--bad);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:14px}td{padding:7px 6px;border-top:1px solid var(--line);vertical-align:top}
.lv{font-weight:700;font-size:12px;white-space:nowrap}.FAIL{color:var(--bad)}.WARN{color:var(--part)}
.PASS{color:var(--ok)}.INFO{color:var(--muted)}
.src{white-space:pre-wrap;font-size:13px;max-height:340px;overflow:auto;background:var(--bg);padding:10px;
border-radius:4px;border:1px solid var(--line)}.q{background:var(--badbg);color:var(--bad);text-decoration:line-through}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:13px;color:var(--muted);margin:6px 0 14px}
.lg{border-radius:3px;padding:1px 4px;border-bottom:2px solid transparent;color:var(--ink)}
"""

JS = """
const claims = JSON.parse(document.getElementById('claims-data').textContent);
const detail = document.getElementById('detail-body');
function show(i){
  document.querySelectorAll('.c.active').forEach(e=>e.classList.remove('active'));
  const el = document.querySelector('[data-i="'+i+'"]'); if(el) el.classList.add('active');
  const c = claims[i]; const lab = LABELS[c.label] || [c.label, ''];
  let h = '<p class="lab">'+esc(lab[0])+'</p><p class="sub">'+esc(lab[1])+'</p>';
  h += '<p>'+esc(c.text)+'</p>';
  if (c.missing.length) h += '<p class="miss">Found in no source: '+c.missing.map(esc).join(', ')+'</p>';
  if (c.evidence) h += '<p class="sub">Closest passage, '+esc(c.source)+' (overlap '+c.score.toFixed(2)+'):</p><blockquote>'+esc(c.evidence)+'</blockquote>';
  detail.innerHTML = h;
}
function esc(s){return String(s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));}
document.querySelectorAll('.c').forEach(e=>{
  e.addEventListener('click',()=>show(e.dataset.i));
  e.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();show(e.dataset.i);}});
});
"""


def _md_inline(text):
    t = html.escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    return t


def _highlight(line_html, claims, used):
    """Wrap each claim's sentence in a span where it appears in this line."""
    for i, c in enumerate(claims):
        if i in used:
            continue
        needle = html.escape(c.text)
        pos = line_html.find(needle)
        if pos < 0:
            continue
        span = (f'<span class="c c-{c.label}" tabindex="0" data-i="{i}" '
                f'title="{html.escape(LABELS.get(c.label, (c.label,))[0])}">{needle}</span>')
        line_html = line_html[:pos] + span + line_html[pos + len(needle):]
        used.add(i)
    return line_html


def brief_to_html(brief, claims):
    out, used, in_list = [], set(), False
    for raw in brief.splitlines():
        line = raw.strip()
        if not line or line in ("---", "***"):
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        plain = re.sub(r"\*\*|`", "", line)
        m = re.match(r"^(#{1,6})\s+(.*)$", plain)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            level = min(len(m.group(1)) + 1, 4)
            out.append(f"<h{level}>{html.escape(m.group(2))}</h{level}>")
            continue
        bullet = re.match(r"^[-*•]\s+(.*)$", plain)
        body = _highlight(html.escape(bullet.group(1) if bullet else plain), claims, used)
        if bullet:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{body}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{body}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def source_to_html(text):
    """Show a source with quarantined text visible but struck through."""
    result = sanitize_text(text)
    escaped = html.escape(text)
    for f in result.findings:
        if f.kind == "invisible_chars" or not f.removed_text.strip():
            continue
        frag = html.escape(f.removed_text)
        escaped = escaped.replace(frag, f'<span class="q" title="{html.escape(f.reason)}">{frag}</span>', 1)
    return escaped


def render_html(title, brief, corpus, report):
    claims = report.claims
    counts = report.claim_summary or {}
    failed = report.failed
    tally = [("supported", "Supported"), ("partial", "Partial"), ("unsupported", "Unsupported"),
             ("absence_claims", "Absence claims"), ("judgment", "Judgments")]
    tally_html = "".join(f"<span>{lab}: {counts.get(k, 0)}</span>" for k, lab in tally)
    rows = "".join(f'<tr><td class="lv {r["level"]}">{r["level"]}</td><td>{html.escape(r["check"])}</td>'
                   f'<td>{html.escape(r["message"])}</td></tr>' for r in report.results)
    sources = "".join(f"<details><summary>{html.escape(n)}</summary><div class='src'>{source_to_html(t)}</div></details>"
                      for n, t in corpus.items())
    legend = "".join(f'<span class="lg c-{k}">{v[0]}</span>' for k, v in LABELS.items())
    data = json.dumps([c.as_dict() for c in claims]).replace("</", "<\\/")
    labels_js = json.dumps(LABELS)
    verdict = ('<span class="verdict v-fail">FAIL</span>' if failed else
               '<span class="verdict v-pass">PASS</span>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Brief audit</title>
<style>{CSS}</style></head><body>
<header><h1>Brief audit: {html.escape(title)}</h1>
<div>{verdict}<span class="sub">{len(corpus)} source document(s), {counts.get('claims', 0)} claim(s) checked.
Automated checks only; an analyst still signs off.</span></div><div class="tally">{tally_html}</div></header>
<div class="wrap"><div class="grid">
<section class="card brief"><h2>The brief, claim by claim</h2><div class="legend">{legend}</div>
{brief_to_html(brief, claims)}</section>
<aside><div class="card" id="detail"><h2>Evidence</h2><div id="detail-body">
<p class="sub">Select any highlighted sentence to see the source passage behind it.</p></div></div></aside>
</div>
<section class="card" style="margin-top:20px"><h2>Checks</h2><table>{rows}</table></section>
<section class="card" style="margin-top:20px"><h2>Sources</h2>
<p class="sub">Struck-through text was quarantined as a suspected prompt injection and never counted as evidence.</p>
{sources}</section></div>
<script id="claims-data" type="application/json">{data}</script>
<script>const LABELS={labels_js};{JS}</script></body></html>"""


def write_html(path, title, brief, corpus, report):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(title, brief, corpus, report))


def to_sarif(brief_path, report, version="0"):
    """SARIF 2.1.0, so results can show up in GitHub code scanning or a SIEM."""
    level = {"FAIL": "error", "WARN": "warning", "INFO": "note"}
    results = [{"ruleId": r["check"], "level": level[r["level"]], "message": {"text": r["message"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": brief_path}}}]}
               for r in report.results if r["level"] in level]
    rules = [{"id": rid, "name": rid} for rid in sorted({r["ruleId"] for r in results})]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "briefaudit", "version": version,
                                          "informationUri": "https://github.com/ktaki8/space-cyber-brief-crew",
                                          "rules": rules}},
                      "results": results}]}
