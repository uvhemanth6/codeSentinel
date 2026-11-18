"""Deterministic reasoning layer (no network, no API key).

Everything here is derived directly from scanner output, so it is labelled `deterministic-rules`
and every statement carries finding IDs that really exist.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ..models.finding import SEVERITY_RANK

EFFORT = {"critical": "medium", "high": "medium", "medium": "low", "low": "low", "info": "low"}


def _top(findings: list[dict], n: int) -> list[dict]:
    return sorted(findings, key=lambda f: -f.get("priority", 0))[:n]


def architectural_risks(result: dict) -> list[dict]:
    findings = result["findings"]
    structure = result.get("structure", {})
    risks: list[dict] = []
    sec = [f for f in findings if f["category"] == "Security"]
    if not structure.get("has_tests") and result["summary"]["files_scanned"] >= 3:
        risks.append({"title": "No automated tests detected",
                      "description": "No test files or test directories were found, so regressions in the flagged "
                                     "areas cannot be caught automatically.", "evidence": "0 test files discovered",
                      "finding_ids": []})
    if not structure.get("has_readme"):
        risks.append({"title": "No README found", "description": "Setup, configuration and threat assumptions are "
                      "undocumented.", "evidence": "No README in repository root", "finding_ids": []})
    if sec:
        per_file = Counter(f["file"] for f in sec)
        top_file, n = per_file.most_common(1)[0]
        if n >= 3 and n / len(sec) >= 0.4:
            risks.append({"title": f"Security findings concentrate in `{top_file}`",
                          "description": "A single module accumulates a large share of the security issues - a "
                                         "strong candidate for focused review or redesign.",
                          "evidence": f"{n} of {len(sec)} security findings", "finding_ids":
                              [f["id"] for f in sec if f["file"] == top_file][:10]})
        secrets = [f for f in sec if f["family"] == "hardcoded-secret"]
        if len({f["file"] for f in secrets}) >= 2:
            risks.append({"title": "Secrets are scattered across multiple files",
                          "description": "Credentials are embedded in several places instead of one configuration "
                                         "boundary, making rotation and auditing difficult.",
                          "evidence": f"{len(secrets)} hard-coded secrets in {len({f['file'] for f in secrets})} files",
                          "finding_ids": [f["id"] for f in secrets][:10]})
    val = [f for f in findings if f["family"] == "missing-validation"]
    if len(val) >= 3:
        risks.append({"title": "Input validation is not a consistent architectural layer",
                      "description": "Multiple request handlers use external input without a shared validation "
                                     "mechanism.", "evidence": f"{len(val)} validation gaps",
                      "finding_ids": [f["id"] for f in val][:10]})
    dups = [f for f in findings if f["family"] in ("duplicate-function", "repeated-code")]
    if len(dups) >= 3:
        risks.append({"title": "Shared logic is copy-pasted instead of centralised",
                      "description": "Repeated functions/blocks suggest a missing shared module or abstraction.",
                      "evidence": f"{len(dups)} duplication findings", "finding_ids": [f["id"] for f in dups][:10]})
    swallow = [f for f in findings if f["family"] == "empty-except"]
    if len(swallow) >= 3:
        risks.append({"title": "Errors are swallowed across the codebase",
                      "description": "Empty exception handlers indicate no consistent error-handling/logging strategy.",
                      "evidence": f"{len(swallow)} swallowed exceptions", "finding_ids": [f["id"] for f in swallow][:10]})
    langs = result.get("languages", {}).get("languages", [])
    partial = sum(l["lines"] for l in langs if l["support"] != "full")
    total = sum(l["lines"] for l in langs) or 1
    if partial / total > 0.3:
        risks.append({"title": "Large share of code only partially analysed",
                      "description": "Over 30% of lines are in languages with generic analyzers only, so coverage is "
                                     "weaker there.", "evidence": f"{round(100 * partial / total)}% of lines",
                      "finding_ids": []})
    return risks


def remediation_plan(findings: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        groups[f["family"]].append(f)
    plan = []
    for fam, items in groups.items():
        best = min(items, key=lambda f: (SEVERITY_RANK[f["severity"]], -f.get("priority", 0)))
        score = sum(f.get("priority", 0) for f in items)
        plan.append({"family": fam, "title": best["title"] if len(items) == 1 else f"{fam.replace('-', ' ').capitalize()} ({len(items)} findings)",
                     "severity": best["severity"], "category": best["category"], "count": len(items),
                     "finding_ids": [f["id"] for f in sorted(items, key=lambda f: -f.get("priority", 0))][:15],
                     "action": best["remediation"], "effort": EFFORT[best["severity"]] if len(items) < 5 else "high",
                     "_score": score})
    plan.sort(key=lambda p: -p["_score"])
    for i, p in enumerate(plan[:15], 1):
        p["order"] = i
        p.pop("_score", None)
    return plan[:15]


def related_groups(findings: list[dict]) -> list[dict]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)
    groups = []
    for file, items in by_file.items():
        cats = {f["category"] for f in items}
        if len(items) >= 4 and len(cats) >= 2:
            groups.append({"label": f"Hotspot: {file}", "reason": f"{len(items)} findings across {', '.join(sorted(cats))}",
                           "finding_ids": [f["id"] for f in _top(items, 10)]})
    groups.sort(key=lambda g: -len(g["finding_ids"]))
    return groups[:8]


def executive_summary(result: dict) -> str:
    s = result["summary"]
    c = s["scores"]["counts"]
    if s["files_scanned"] == 0:
        return "No analysable source files were found, so no scores or findings were produced."
    langs = ", ".join(l["language"] for l in result["languages"]["languages"][:4]) or "unknown languages"
    parts = [f"CodeSentinel analysed {s['files_scanned']} files ({s['code_lines']} lines) written mainly in {langs}"
             + (f" using {', '.join(result['structure']['frameworks'])}" if result["structure"].get("frameworks") else "")
             + f". It reported {c['total']} findings: {c['critical']} critical, {c['high']} high, {c['medium']} medium, "
               f"{c['low']} low."]
    dims = s["scores"]["dimensions"]
    worst = min(dims.values(), key=lambda d: d["score"] if d["score"] is not None else 101)
    parts.append(f"The repository health indicator is {s['scores']['overall']}/100 (grade {s['scores']['grade']}); the "
                 f"weakest dimension is {worst['label']} ({worst['score']}/100). The code slop score is "
                 f"{s['scores']['slop']['score']}/100 (higher is worse).")
    top = _top([f for f in result["findings"] if f["category"] == "Security"], 1)
    if top:
        t = top[0]
        parts.append(f"The highest-priority security item is “{t['title']}” in {t['file']}"
                     + (f":{t['line']}" if t.get("line") else "") + f" ({t['severity']}, {t['verification'].replace('-', ' ')}).")
    parts.append("Findings marked 'potential risk' need human confirmation; scores are heuristics, not a security "
                 "certification.")
    return " ".join(parts)


def build_deterministic_review(result: dict) -> dict:
    findings = result["findings"]
    return {
        "mode": "deterministic", "source": "deterministic-rules", "verified": True,
        "generated_by": "CodeSentinel deterministic reasoning engine (no external AI used)",
        "executive_summary": executive_summary(result),
        "top_risks": [{"finding_id": f["id"], "title": f["title"], "severity": f["severity"], "file": f["file"],
                       "line": f.get("line"), "why": f["impact"]} for f in _top(findings, 5)],
        "architectural_risks": architectural_risks(result),
        "remediation_plan": remediation_plan(findings),
        "related_issue_groups": related_groups(findings),
    }
