"""The 14-stage CodeSentinel auditing pipeline (stages 2-14; ingestion happens in runner.py)."""
from __future__ import annotations

import time
from collections import Counter
from typing import Callable

# Import analyzers for registration side effects.
from ..analyzers import (bandit_runner, config_files, gaps_clike, gaps_python, loose_ends,  # noqa: F401
                         python_ast_security, security_patterns, semgrep_runner, slop)
from ..analyzers.base import STAGES, analyzers_for, all_analyzers
from ..ai.deterministic import build_deterministic_review
from ..models.finding import SEVERITY_RANK, Finding
from ..models.source import ProjectContext
from ..utils.redact import mask_secrets
from . import normalize, scoring, structure
from .discovery import discover
from .languages import all_languages

STAGE_LABELS = [
    ("ingestion", "Repository ingestion"), ("discovery", "File discovery"), ("languages", "Language identification"),
    ("structure", "Project structure analysis"), ("security", "Security scanning"), ("slop", "Code slop detection"),
    ("gaps", "Coding gap detection"), ("loose_ends", "Loose-end detection"), ("normalize", "Finding normalization"),
    ("dedupe", "Deduplication"), ("ai", "AI reasoning (deterministic)"), ("priority", "Severity prioritization"),
    ("scoring", "Repository health scoring"), ("report", "Report generation"),
]
VERIF_FACTOR = {"static-match": 1.0, "potential-risk": 0.7, "heuristic": 0.5}
CONF_FACTOR = {"high": 1.0, "medium": 0.75, "low": 0.5}
SEV_WEIGHT = {"critical": 100, "high": 60, "medium": 30, "low": 10, "info": 2}
CAT_BOOST = {"Security": 1.25, "Coding Gaps": 1.0, "Loose Ends": 0.9, "Code Slop": 0.8}

Progress = Callable[[str, str, str], None]


def _noop(stage: str, status: str, detail: str = "") -> None:
    return None


def priority_score(f: Finding) -> float:
    return round(SEV_WEIGHT[f.severity] * CONF_FACTOR[f.confidence] * VERIF_FACTOR.get(f.verification, 0.5)
                 * CAT_BOOST.get(f.category, 1.0), 1)


def run_pipeline(root: str, settings: dict, meta: dict, progress: Progress = _noop, ingestion: dict | None = None,
                 max_file_bytes: int = 1024 * 1024) -> dict:
    t0 = time.time()
    progress("ingestion", "done", f"{(ingestion or {}).get('entries', 'n/a')} archive entries" if ingestion else "local copy")

    progress("discovery", "running", "")
    files, skipped, lang_stats = discover(root, max_file_bytes)
    skip_counts = Counter(s["reason"] for s in skipped)
    progress("discovery", "done", f"{len(files)} files, {len(skipped)} excluded")

    progress("languages", "running", "")
    support = Counter(f.language.support if f.language else "unsupported" for f in files)
    progress("languages", "done", ", ".join(l["language"] for l in lang_stats["languages"][:5]) or "none")

    ctx = ProjectContext(root=root, files=files, settings=settings, skipped=skipped)
    progress("structure", "running", "")
    structure.collect_manifests(ctx)
    ctx.frameworks = structure.detect_frameworks(ctx)
    struct = structure.analyze_structure(ctx)
    progress("structure", "done", ", ".join(ctx.frameworks) or "no framework detected")

    raw: list[Finding] = []
    analyzer_status: list[dict] = []
    for stage in STAGES:
        progress(stage, "running", "")
        count = 0
        for an in analyzers_for(stage):
            entry = {"name": an.name, "stage": stage, "status": "ran", "findings": 0, "error": None}
            ok, why = an.available()
            if not ok and an.name not in ("bandit",):  # bandit reports its own status in ctx.tools
                entry.update(status="skipped", error=why)
                analyzer_status.append(entry)
                ctx.tools.setdefault(an.name, {"status": "unavailable", "reason": why})
                continue
            produced: list[Finding] = []
            try:
                for sf in files:
                    if an.applies_to(sf):
                        try:
                            produced.extend(an.analyze_file(sf, ctx) or [])
                        except Exception as e:  # noqa: BLE001 - one bad file/analyzer must not kill the scan
                            entry["error"] = f"{sf.rel}: {e.__class__.__name__}"
                produced.extend(an.analyze_project(ctx) or [])
            except Exception as e:  # noqa: BLE001
                entry.update(status="failed", error=f"{e.__class__.__name__}: {e}")
            entry["findings"] = len(produced)
            count += len(produced)
            raw.extend(produced)
            analyzer_status.append(entry)
        progress(stage, "done", f"{count} raw findings")

    progress("normalize", "running", "")
    findings = normalize.normalize(raw)
    progress("normalize", "done", f"{len(findings)} findings")
    progress("dedupe", "running", "")
    findings, removed = normalize.deduplicate(findings)
    progress("dedupe", "done", f"{removed} duplicates merged")

    for f in findings:
        f.dimension = scoring.dimension_of(f)
    progress("priority", "running", "")
    for f in findings:
        f.priority = priority_score(f)
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], -f.priority, f.file, f.line or 0))
    progress("priority", "done", "ranked by severity × confidence × verification")

    code_lines = sum(len([l for l in sf.lines if l.strip()]) for sf in files if sf.language and sf.language.kind == "code")
    all_lines = sum(len(sf.lines) for sf in files)
    progress("scoring", "running", "")
    scores = scoring.compute_scores(findings, code_lines, settings)
    progress("scoring", "done", f"health {scores['overall']}")

    for f in findings:  # credentials must never be stored or exported in clear text
        f.evidence = mask_secrets(f.evidence)
        for c in f.context:
            c["text"] = mask_secrets(c["text"])
        for o in f.occurrences:
            if "snippet" in o:
                o["snippet"] = mask_secrets(o["snippet"])
    fdicts = [f.to_dict() for f in findings]
    per_file = Counter(f.file for f in findings)
    file_rows = [{"path": sf.rel, "language": sf.lang_name or "Unsupported", "lines": len(sf.lines), "bytes": sf.size,
                  "support": sf.language.support if sf.language else "unsupported",
                  "findings": per_file.get(sf.rel, 0)} for sf in files]
    result = {
        "meta": {**meta, "duration_seconds": round(time.time() - t0, 2), "engine": "CodeSentinel 1.0"},
        "summary": {"files_scanned": len(files), "files_skipped": len(skipped), "total_lines": all_lines,
                    "code_lines": code_lines, "scores": scores, "duplicates_merged": removed,
                    "support_breakdown": dict(support)},
        "findings": fdicts, "files": file_rows,
        "languages": lang_stats, "structure": struct, "tools": ctx.tools, "analyzers": analyzer_status,
        "skipped": {"counts": dict(skip_counts), "sample": skipped[:100]},
        "supported_languages": [{"name": l.name, "support": l.support, "extensions": list(l.extensions)} for l in all_languages()],
        "settings": settings,
        "ingestion": ingestion or {},
    }
    progress("ai", "running", "")
    result["ai"] = {"deterministic": build_deterministic_review(result), "gemini": None}
    progress("ai", "done", "executive summary generated from scanner facts")
    progress("report", "done", "JSON/Markdown/HTML exports available")
    return result
