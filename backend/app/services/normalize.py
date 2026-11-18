"""Stages 9-10: finding normalisation and de-duplication."""
from __future__ import annotations

from ..models.finding import CONFIDENCE_RANK, SEVERITY_RANK, Finding

VERIF_RANK = {"static-match": 0, "potential-risk": 1, "heuristic": 2}


def normalize(findings: list[Finding]) -> list[Finding]:
    out = []
    for f in findings:
        if f.severity not in SEVERITY_RANK:
            f.severity = "low"
        if f.confidence not in CONFIDENCE_RANK:
            f.confidence = "medium"
        f.evidence = (f.evidence or "").strip()[:500]
        if f.line is not None and (not isinstance(f.line, int) or f.line < 1):
            f.line = None
        f.file = (f.file or "").replace("\\", "/")
        out.append(f)
    return out


def _rank(f: Finding):
    return (SEVERITY_RANK[f.severity], CONFIDENCE_RANK[f.confidence], VERIF_RANK.get(f.verification, 3),
            0 if f.cwe else 1, f.rule_id)


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge findings that describe the same issue at the same place.

    Key = (file, line, family). Different tools (Bandit, AST, regex, Semgrep) reporting the same
    family on the same line collapse into the strongest finding; `detected_by` records corroboration.
    """
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.file, f.line if f.line is not None else f"rule:{f.rule_id}", f.family)
        groups.setdefault(key, []).append(f)
    merged: list[Finding] = []
    removed = 0
    for group in groups.values():
        group.sort(key=_rank)
        win = group[0]
        if len(group) > 1:
            removed += len(group) - 1
            sources = []
            for g in group:
                for s in g.detected_by:
                    if s not in sources:
                        sources.append(s)
            win.detected_by = sources
            if len(sources) > 1:
                win.confidence = "high"  # independent tools agree
                if "corroborated" not in win.tags:
                    win.tags.append("corroborated")
            if not win.cwe:
                win.cwe = next((g.cwe for g in group if g.cwe), None)
            others = [g.rule_id for g in group[1:] if g.rule_id != win.rule_id]
            if others:
                win.tags.append("also:" + ",".join(sorted(set(others))))
        merged.append(win)
    merged.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line or 0))
    return merged, removed
