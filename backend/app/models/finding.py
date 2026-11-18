"""Common finding format shared by every analyzer."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = more severe
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

CAT_SECURITY = "Security"
CAT_SLOP = "Code Slop"
CAT_GAPS = "Coding Gaps"
CAT_LOOSE = "Loose Ends"
CATEGORIES = [CAT_SECURITY, CAT_SLOP, CAT_GAPS, CAT_LOOSE]

# The six gap/loose-end classes requested by the product spec.
GAP_INCOMPLETE = "Incomplete Implementation"
GAP_ERRORS = "Error Handling Gaps"
GAP_VALIDATION = "Validation Gaps"
GAP_DEBUG = "Debugging Leftovers"
GAP_CONFIG = "Configuration Issues"
GAP_MAINT = "Maintainability Issues"
GAP_CLASSES = [GAP_INCOMPLETE, GAP_ERRORS, GAP_VALIDATION, GAP_DEBUG, GAP_CONFIG, GAP_MAINT]

# Verification status: how sure the *scanner* is. AI output never changes this.
V_STATIC = "static-match"        # deterministic pattern/AST match of a known-bad construct
V_POTENTIAL = "potential-risk"   # suspicious; needs data-flow / human confirmation
V_HEURISTIC = "heuristic"        # measurable quality metric or threshold


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    subcategory: str
    severity: str
    file: str
    line: int | None
    evidence: str
    explanation: str
    impact: str
    remediation: str
    confidence: str = "medium"
    source: str = "custom"
    verification: str = V_POTENTIAL
    family: str = ""
    language: str | None = None
    cwe: str | None = None
    end_line: int | None = None
    context: list[dict[str, Any]] = field(default_factory=list)
    occurrences: list[dict[str, Any]] = field(default_factory=list)
    detected_by: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    dimension: str = ""
    priority: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.family:
            self.family = self.rule_id
        if not self.detected_by:
            self.detected_by = [self.source]
        if not self.id:
            raw = f"{self.rule_id}|{self.file}|{self.line}|{self.evidence.strip()[:200]}"
            self.id = "F-" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:10]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
