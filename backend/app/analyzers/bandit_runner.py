"""Bandit integration (Python). Bandit only parses files - it never executes them."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from ..config import IGNORED_DIRS
from ..security.rules import PLACEHOLDER
from ..models.finding import CAT_SECURITY, V_POTENTIAL, V_STATIC, Finding
from ..models.source import ProjectContext
from .base import Analyzer, build_finding, register

SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CONF = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
# Map Bandit test IDs to our dedupe "families" so Bandit and custom rules merge cleanly.
FAMILY = {
    "B608": "sql-injection", "B602": "command-injection", "B605": "command-injection", "B604": "command-injection",
    "B603": "command-injection", "B606": "command-injection", "B607": "command-injection",
    "B301": "unsafe-deserialization", "B302": "unsafe-deserialization", "B403": "unsafe-deserialization",
    "B506": "unsafe-deserialization", "B307": "dangerous-function", "B102": "dangerous-function",
    "B324": "weak-crypto", "B303": "weak-crypto", "B304": "weak-crypto", "B311": "weak-crypto",
    "B105": "hardcoded-secret", "B106": "hardcoded-secret", "B107": "hardcoded-secret",
    "B501": "tls-verification-disabled", "B201": "debug-enabled", "B104": "bind-all", "B108": "insecure-file-ops",
    "B306": "insecure-file-ops", "B103": "insecure-file-ops", "B701": "xss", "B703": "xss", "B702": "xss",
    "B310": "insecure-http", "B113": "missing-timeout", "B101": "assert-used", "B110": "silent-except",
    "B112": "silent-except", "B202": "path-traversal", "B411": "dangerous-function",
}
SUBCAT = {"sql-injection": "Injection", "command-injection": "Injection", "unsafe-deserialization": "Deserialization",
          "weak-crypto": "Cryptography", "hardcoded-secret": "Secrets", "tls-verification-disabled": "Transport Security",
          "xss": "Cross-Site Scripting", "path-traversal": "File Handling", "insecure-file-ops": "File Handling",
          "dangerous-function": "Dangerous Functions", "insecure-http": "Transport Security"}
SKIP_IDS = {"B603", "B607", "B311", "B113", "B101", "B110", "B112", "B404", "B405", "B406", "B407", "B408", "B409", "B410", "B413", "B403", "B401",
            "B402", "B412"}  # asserts / silent excepts handled by our own gap analyzer; import-only warnings are noise


@register
class BanditAnalyzer(Analyzer):
    name = "bandit"
    stage = "security"
    languages = ("Python",)

    def available(self):
        try:
            r = subprocess.run([sys.executable, "-m", "bandit", "--version"], capture_output=True, timeout=20)
            return (r.returncode == 0, "" if r.returncode == 0 else "bandit is not installed (pip install bandit)")
        except (OSError, subprocess.SubprocessError):
            return False, "bandit could not be started"

    def analyze_project(self, ctx: ProjectContext):
        py_files = ctx.code_files("Python")
        ok, why = self.available()
        if not ok:
            ctx.tools["bandit"] = {"status": "unavailable", "reason": why}
            return []
        if not py_files:
            ctx.tools["bandit"] = {"status": "skipped", "reason": "no Python files"}
            return []
        by_path = {os.path.realpath(f.abs_path): f for f in py_files}
        cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", "--exit-zero", "-x",
               ",".join(os.path.join(ctx.root, d) for d in sorted(IGNORED_DIRS)), "-r", ctx.root]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=ctx.root,
                                  env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            data = json.loads(proc.stdout or "{}")
        except subprocess.TimeoutExpired:
            ctx.tools["bandit"] = {"status": "failed", "reason": "timed out"}
            return []
        except (ValueError, OSError) as e:
            ctx.tools["bandit"] = {"status": "failed", "reason": f"unparseable output ({e.__class__.__name__})"}
            return []
        out: list[Finding] = []
        for r in data.get("results", []):
            tid = r.get("test_id", "")
            sf = by_path.get(os.path.realpath(r.get("filename", "")))
            if sf is None or tid in SKIP_IDS or (sf.is_test and tid in ("B105", "B106", "B107", "B108", "B311")):
                continue
            fam = FAMILY.get(tid, f"bandit-{tid.lower()}")
            if fam == "hardcoded-secret":
                src_line = sf.lines[r.get("line_number", 1) - 1] if 0 < r.get("line_number", 0) <= len(sf.lines) else ""
                vals = re.findall(r"""["']([^"']*)["']""", src_line)
                if not vals or any(PLACEHOLDER.match(v) or "${" in v or len(v) < 4 for v in vals[-1:]):
                    continue
            sev = SEV.get(r.get("issue_severity", "LOW"), "low")
            conf = CONF.get(r.get("issue_confidence", "LOW"), "low")
            cwe = (r.get("issue_cwe") or {}).get("id")
            out.append(build_finding(
                sf, rule_id=f"BANDIT-{tid}", title=r.get("test_name", tid).replace("_", " ").capitalize(),
                category=CAT_SECURITY, subcategory=SUBCAT.get(fam, "Security Misconfiguration"), severity=sev,
                line=r.get("line_number"), explanation=r.get("issue_text", ""),
                impact="Flagged by Bandit's security plugin; exploitability depends on whether untrusted data "
                       "reaches this code.",
                remediation=f"See Bandit documentation for {tid}: {r.get('more_info', '')}".strip(),
                confidence=conf, source="bandit", verification=V_STATIC if conf == "high" else V_POTENTIAL,
                family=fam, cwe=f"CWE-{cwe}" if cwe else None))
        ctx.tools["bandit"] = {"status": "ran", "findings": len(out)}
        return out
