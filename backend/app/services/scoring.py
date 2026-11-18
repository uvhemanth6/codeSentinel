"""Stage 13: transparent repository health scoring.

Every finding is assigned to exactly ONE dimension, so nothing is double counted:
  Security        <- category Security
  Completeness    <- Incomplete Implementation, Validation Gaps
  Code Quality    <- Error Handling Gaps, Debugging Leftovers, Configuration Issues, naming/unused-code/exceptions slop
  Maintainability <- complexity/duplication/dead-code/abstraction/boilerplate/dependency slop, Maintainability Issues

points      = sum(severity_points[sev] * confidence_factor[conf])
dim score   = 100 * exp(-points / (norm * (1 + KLOC * size_factor)))     (100 = nothing found)
health      = weighted mean of the four dimension scores (weights configurable)
code slop   = 100 * (1 - exp(-(slop points per 100 lines) / slop_norm))     (higher = worse)

This is a heuristic indicator of detected issues - not a security certification.
"""
from __future__ import annotations

import math

from ..models.finding import (CAT_SECURITY, CAT_SLOP, GAP_DEBUG, GAP_ERRORS, GAP_INCOMPLETE, GAP_CONFIG,
                              GAP_MAINT, GAP_VALIDATION, SEVERITIES, Finding)

DIMENSIONS = ("security", "quality", "completeness", "maintainability")
LABELS = {"security": "Security", "quality": "Code Quality", "completeness": "Completeness",
          "maintainability": "Maintainability"}
MAINT_SLOP = {"Complexity", "Duplication", "Dead Code", "Unnecessary Abstraction", "Boilerplate", "Dependencies"}


def dimension_of(f: Finding) -> str:
    if f.category == CAT_SECURITY:
        return "security"
    if f.category == CAT_SLOP:
        return "maintainability" if f.subcategory in MAINT_SLOP else "quality"
    if f.subcategory in (GAP_INCOMPLETE, GAP_VALIDATION):
        return "completeness"
    if f.subcategory == GAP_MAINT:
        return "maintainability"
    return "quality"


def _points(f: Finding, s: dict) -> float:
    return s["severity_points"].get(f.severity, 0) * s["confidence_factor"].get(f.confidence, 1.0)


def grade(score: float | None) -> str:
    if score is None:
        return "n/a"
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def compute_scores(findings: list[Finding], code_lines: int, settings: dict) -> dict:
    kloc = code_lines / 1000.0
    size_mult = 1 + kloc * settings["size_factor"]
    dims: dict[str, dict] = {}
    for d in DIMENSIONS:
        items = [f for f in findings if f.dimension == d]
        pts = round(sum(_points(f, settings) for f in items), 2)
        norm = settings["norms"][d]
        denom = norm * size_mult
        score = round(100 * math.exp(-pts / denom)) if code_lines > 0 else None
        by_sev = {s: sum(1 for f in items if f.severity == s) for s in SEVERITIES}
        dims[d] = {
            "label": LABELS[d], "score": score, "grade": grade(score), "findings": len(items), "points": pts,
            "by_severity": by_sev, "norm": norm, "denominator": round(denom, 2),
            "explanation": (f"{len(items)} findings contribute {pts} penalty points "
                            f"({', '.join(f'{v} {k}' for k, v in by_sev.items() if v) or 'none'}). "
                            f"score = 100 × e^(−{pts} / {round(denom, 1)}), where {round(denom, 1)} = norm {norm} × "
                            f"(1 + {kloc:.2f} KLOC × {settings['size_factor']})."),
        }
    w = settings["weights"]
    total_w = sum(max(0.0, float(w.get(d, 0))) for d in DIMENSIONS) or 1.0
    overall = None
    if code_lines > 0:
        overall = round(sum(max(0.0, float(w.get(d, 0))) * (dims[d]["score"] or 0) for d in DIMENSIONS) / total_w)
    slop_items = [f for f in findings if f.category == CAT_SLOP]
    slop_pts = round(sum(_points(f, settings) for f in slop_items), 2)
    density = slop_pts / max(1.0, code_lines / 100.0)
    slop_score = round(100 * (1 - math.exp(-density / settings["norms"]["slop"]))) if code_lines > 0 else None
    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    return {
        "overall": overall, "grade": grade(overall),
        "dimensions": dims,
        "slop": {"score": slop_score, "findings": len(slop_items), "points": slop_pts,
                 "density_per_100_lines": round(density, 2),
                 "explanation": (f"{len(slop_items)} code-slop findings = {slop_pts} weighted points over "
                                 f"{code_lines} lines ({round(density, 2)} points per 100 lines). "
                                 f"score = 100 × (1 − e^(−density / {settings['norms']['slop']})). Higher means more "
                                 "detected code-quality concerns; it measures patterns, not authorship.")},
        "weights": {d: round(max(0.0, float(w.get(d, 0))) / total_w, 3) for d in DIMENSIONS},
        "counts": {"total": len(findings), **sev_counts},
        "code_lines": code_lines,
        "method": ("Heuristic indicator derived from automated findings. Each finding counts toward exactly one "
                   "dimension; duplicates reported by several tools are merged first. This is NOT a formal security "
                   "certification or guarantee of absence of vulnerabilities."),
    }
