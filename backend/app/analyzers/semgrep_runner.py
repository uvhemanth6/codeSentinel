"""Optional Semgrep integration using the bundled *local* rule file (no registry/network access)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from ..config import Config
from ..models.finding import CAT_SECURITY, V_POTENTIAL, Finding
from ..models.source import ProjectContext
from .base import Analyzer, build_finding, register

SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep_json(data: dict, by_path: dict) -> list[Finding]:
    out: list[Finding] = []
    for r in data.get("results", []):
        sf = by_path.get(os.path.realpath(r.get("path", ""))) or by_path.get(r.get("path", ""))
        if sf is None:
            continue
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        rule = r.get("check_id", "semgrep").split(".")[-1]
        out.append(build_finding(
            sf, rule_id=f"SEMGREP-{rule}", title=meta.get("title") or rule.replace("-", " ").capitalize(),
            category=CAT_SECURITY, subcategory=meta.get("subcategory", "Security Misconfiguration"),
            severity=SEV.get(str(extra.get("severity", "INFO")).upper(), "low"),
            line=(r.get("start") or {}).get("line"), end_line=(r.get("end") or {}).get("line"),
            explanation=extra.get("message", ""), impact=meta.get("impact", "See rule message."),
            remediation=meta.get("fix", "Review the flagged construct and apply the recommended secure alternative."),
            confidence=str(meta.get("confidence", "medium")).lower(), source="semgrep", verification=V_POTENTIAL,
            family=meta.get("family", f"semgrep-{rule}"), cwe=str(cwe).split(":")[0] if cwe else None))
    return out


@register
class SemgrepAnalyzer(Analyzer):
    name = "semgrep"
    stage = "security"

    def available(self):
        if not shutil.which("semgrep"):
            return False, "semgrep is not installed (optional: pip install semgrep)"
        if not os.path.exists(Config.SEMGREP_RULES):
            return False, "bundled semgrep rules missing"
        return True, ""

    def analyze_project(self, ctx: ProjectContext):
        ok, why = self.available()
        if not ok:
            ctx.tools["semgrep"] = {"status": "unavailable", "reason": why}
            return []
        by_path = {os.path.realpath(f.abs_path): f for f in ctx.files if f.language and f.language.support == "full"}
        cmd = ["semgrep", "--config", str(Config.SEMGREP_RULES), "--json", "--quiet", "--metrics=off",
               "--disable-version-check", "--timeout", "20", "--max-target-bytes", "1000000", ctx.root]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240, cwd=ctx.root)
            data = json.loads(proc.stdout or "{}")
        except subprocess.TimeoutExpired:
            ctx.tools["semgrep"] = {"status": "failed", "reason": "timed out"}
            return []
        except (ValueError, OSError) as e:
            ctx.tools["semgrep"] = {"status": "failed", "reason": f"unparseable output ({e.__class__.__name__})"}
            return []
        found = parse_semgrep_json(data, by_path)
        ctx.tools["semgrep"] = {"status": "ran", "findings": len(found)}
        return found
