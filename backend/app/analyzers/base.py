"""Analyzer plugin interface + registry.

To add an analyzer: subclass `Analyzer`, set `stage`, and decorate with `@register`.
The pipeline never needs to change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..models.finding import Finding, V_POTENTIAL
from ..models.source import ProjectContext, SourceFile

STAGES = ("security", "slop", "gaps", "loose_ends")


class Analyzer(ABC):
    name: str = "analyzer"
    stage: str = "security"          # one of STAGES
    languages: tuple[str, ...] = ()  # empty => any language

    def applies_to(self, sf: SourceFile) -> bool:
        if not sf.language:
            return False
        return not self.languages or sf.lang_name in self.languages

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext) -> Iterable[Finding]:
        return []

    def analyze_project(self, ctx: ProjectContext) -> Iterable[Finding]:
        return []

    def available(self) -> tuple[bool, str]:
        """(usable, reason-if-not). Lets optional tool wrappers degrade gracefully."""
        return True, ""


_ANALYZERS: list[Analyzer] = []


def register(cls):
    _ANALYZERS.append(cls())
    return cls


def analyzers_for(stage: str) -> list[Analyzer]:
    return [a for a in _ANALYZERS if a.stage == stage]


def all_analyzers() -> list[Analyzer]:
    return list(_ANALYZERS)


# ---------------------------------------------------------------------------
def build_finding(sf: SourceFile, *, rule_id: str, title: str, category: str, subcategory: str, severity: str,
                  line: int | None, explanation: str, impact: str, remediation: str, confidence: str = "medium",
                  source: str = "custom", verification: str = V_POTENTIAL, family: str = "", cwe: str | None = None,
                  evidence: str | None = None, end_line: int | None = None, tags: list[str] | None = None,
                  occurrences: list[dict] | None = None, ctx_lines: int = 2) -> Finding:
    """Create a Finding with source evidence and surrounding context taken from the real file."""
    lines = sf.lines
    context: list[dict] = []
    if line and 1 <= line <= len(lines):
        lo, hi = max(1, line - ctx_lines), min(len(lines), (end_line or line) + ctx_lines)
        hi = min(hi, lo + 14)
        context = [{"line": n, "text": lines[n - 1][:300]} for n in range(lo, hi + 1)]
        if evidence is None:
            evidence = lines[line - 1].strip()
    return Finding(
        rule_id=rule_id, title=title, category=category, subcategory=subcategory, severity=severity,
        file=sf.rel, line=line, end_line=end_line, evidence=(evidence or "")[:500], explanation=explanation,
        impact=impact, remediation=remediation, confidence=confidence, source=source, verification=verification,
        family=family or rule_id, language=sf.lang_name, cwe=cwe, context=context, tags=tags or [],
        occurrences=occurrences or [],
    )
