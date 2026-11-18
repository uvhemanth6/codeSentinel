"""Stage 14: report generation (JSON / Markdown / self-contained HTML). All dynamic text is escaped."""
from __future__ import annotations

import html
import json
import time

DISCLAIMER = ("CodeSentinel produces heuristic findings from automated analysis. Scores are indicators, not a security "
              "certification. Items marked 'potential risk' or 'heuristic' require human verification.")


def to_json(scan: dict, reviews: dict) -> str:
    result = scan["result"]
    out = {"scan": {k: scan[k] for k in ("id", "name", "source_type", "source_ref", "created_at", "finished_at")},
           "summary": result["summary"], "structure": result["structure"], "languages": result["languages"],
           "tools": result["tools"], "analyzers": result["analyzers"], "findings": [
               {**f, "review": reviews.get(f["id"], {"reviewed": False, "note": ""})} for f in result["findings"]],
           "ai": result.get("ai"), "disclaimer": DISCLAIMER}
    return json.dumps(out, indent=2)


def to_markdown(scan: dict, reviews: dict) -> str:
    r = scan["result"]
    s = r["summary"]["scores"]
    lines = [f"# CodeSentinel report — {scan['name']}", "",
             f"*Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}* · scan `{scan['id']}`", "",
             f"> {DISCLAIMER}", "", "## Scores", "", "| Metric | Score |", "|---|---|",
             f"| Repository health | **{s['overall']}/100** (grade {s['grade']}) |"]
    for d in s["dimensions"].values():
        lines.append(f"| {d['label']} | {d['score']}/100 |")
    lines += [f"| Code slop (higher = worse) | {s['slop']['score']}/100 |", "",
              f"**Findings:** {s['counts']['total']} total — {s['counts']['critical']} critical, "
              f"{s['counts']['high']} high, {s['counts']['medium']} medium, {s['counts']['low']} low.", "",
              "## Executive summary", "", r["ai"]["deterministic"]["executive_summary"], ""]
    gem = r["ai"].get("gemini")
    if gem and gem.get("mode") == "gemini":
        lines += ["### AI-generated hypotheses (unverified)", "", gem["review"]["executive_summary"], ""]
    lines += ["## Findings", ""]
    for f in r["findings"]:
        rv = reviews.get(f["id"], {})
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        lines += [f"### [{f['severity'].upper()}] {f['title']}", "",
                  f"- **ID:** {f['id']} · **Rule:** {f['rule_id']} · **Category:** {f['category']} / {f['subcategory']}",
                  f"- **Location:** `{loc}` · **Confidence:** {f['confidence']} · **Verification:** {f['verification']} · "
                  f"**Detected by:** {', '.join(f['detected_by'])}"
                  + (" · **Reviewed**" if rv.get("reviewed") else ""),
                  "", "```", f["evidence"], "```", "", f"**Why it matters:** {f['explanation']}", "",
                  f"**Impact:** {f['impact']}", "", f"**Fix:** {f['remediation']}", ""]
    return "\n".join(lines)


def to_html(scan: dict, reviews: dict) -> str:
    e = html.escape
    r = scan["result"]
    s = r["summary"]["scores"]
    color = {"critical": "#ff5470", "high": "#ff8a4c", "medium": "#f5c451", "low": "#4cc9f0", "info": "#8b93b3"}
    rows = []
    for f in r["findings"]:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        rv = reviews.get(f["id"], {})
        rows.append(
            f"<article><h3><span class='sev' style='background:{color.get(f['severity'], '#888')}'>{e(f['severity'])}</span> "
            f"{e(f['title'])}{' <em>(reviewed)</em>' if rv.get('reviewed') else ''}</h3>"
            f"<p class='meta'>{e(f['id'])} · {e(f['rule_id'])} · {e(f['category'])} / {e(f['subcategory'])} · "
            f"<code>{e(loc)}</code> · confidence {e(f['confidence'])} · {e(f['verification'])} · "
            f"{e(', '.join(f['detected_by']))}</p><pre>{e(f['evidence'])}</pre>"
            f"<p><b>Why:</b> {e(f['explanation'])}</p><p><b>Impact:</b> {e(f['impact'])}</p>"
            f"<p><b>Fix:</b> {e(f['remediation'])}</p></article>")
    dims = "".join(f"<div class='card'><span>{e(d['label'])}</span><b>{d['score']}</b></div>" for d in s["dimensions"].values())
    ai_html = ""
    gem = r["ai"].get("gemini")
    if gem and gem.get("mode") == "gemini":
        ai_html = (f"<h2>AI-generated hypotheses <small>(unverified)</small></h2><p>{e(gem['review']['executive_summary'])}</p>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CodeSentinel — {e(scan['name'])}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{{font:15px/1.5 system-ui,sans-serif;background:#0b1020;color:#e6e9f5;margin:0;padding:32px;max-width:980px;margin:auto}}
h1,h2{{color:#fff}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{background:#141b34;border:1px solid #27305a;border-radius:12px;padding:14px 18px;min-width:130px}}
.card span{{display:block;color:#9aa3c7;font-size:12px}}.card b{{font-size:28px;color:#22d3ee}}article{{background:#101730;border:1px solid #27305a;border-radius:12px;padding:16px;margin:14px 0}}
.sev{{color:#0b1020;border-radius:6px;padding:2px 8px;font-size:12px;text-transform:uppercase}}.meta{{color:#9aa3c7;font-size:12px}}
pre{{background:#070b18;padding:10px;border-radius:8px;overflow:auto}}small,em{{color:#9aa3c7}}</style></head><body>
<h1>CodeSentinel report — {e(scan['name'])}</h1><p><em>{e(DISCLAIMER)}</em></p>
<div class="cards"><div class="card"><span>Repository health</span><b>{s['overall']}</b></div>{dims}
<div class="card"><span>Code slop (↑ worse)</span><b>{s['slop']['score']}</b></div>
<div class="card"><span>Findings</span><b>{s['counts']['total']}</b></div></div>
<h2>Executive summary</h2><p>{e(r['ai']['deterministic']['executive_summary'])}</p>{ai_html}
<h2>Findings</h2>{''.join(rows)}</body></html>"""
