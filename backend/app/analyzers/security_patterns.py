"""Language-aware regex security engine driven by `security/rules.py`."""
from __future__ import annotations

import re

from ..models.finding import CAT_SECURITY, Finding
from ..models.source import ProjectContext, SourceFile
from ..security.rules import RULES, Rule
from .base import Analyzer, build_finding, register

MAX_LINE = 1500
SECRET_FILE_NAMES = re.compile(r"(?i)(^|/)(\.env(\.(?!example|sample|template)\w+)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|"
                               r"[^/]+\.(pem|p12|pfx|jks|keystore)|credentials\.json|service[-_]account[^/]*\.json|"
                               r"\.pgpass|\.netrc|\.htpasswd)$")


@register
class SecurityPatternAnalyzer(Analyzer):
    name = "security-patterns"
    stage = "security"

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        if not sf.language:
            return []
        out: list[Finding] = []
        lang = sf.lang_name
        nocomment_lines = None
        blanked_lines = None
        for rule in RULES:
            if rule.langs is not None and lang not in rule.langs:
                continue
            if rule.skip_tests and sf.is_test:
                continue
            if rule.file_requires and not rule.file_requires.search(sf.text):
                continue
            if rule.file_excludes and rule.file_excludes.search(sf.text):
                continue
            if rule.view == "blanked":
                if blanked_lines is None:
                    blanked_lines = sf.blanked.split("\n")
                view = blanked_lines
            else:
                if nocomment_lines is None:
                    nocomment_lines = sf.nocomment.split("\n")
                view = nocomment_lines
            raw = sf.lines
            for idx, line in enumerate(view):
                if not line.strip() or len(line) > MAX_LINE:
                    continue
                m = rule.pattern.search(line)
                if not m:
                    continue
                overrides: dict = {}
                if rule.check:
                    res = rule.check(m, view, idx, sf)
                    if not res:
                        continue
                    if isinstance(res, dict):
                        overrides = res
                evidence = raw[idx].strip() if idx < len(raw) else line.strip()
                out.append(build_finding(
                    sf, rule_id=rule.id, title=overrides.get("title", rule.title), category=CAT_SECURITY,
                    subcategory=rule.sub, severity=overrides.get("severity", rule.severity), line=idx + 1,
                    explanation=rule.explanation, impact=rule.impact, remediation=rule.remediation,
                    confidence=overrides.get("confidence", rule.confidence), source="custom-rules",
                    verification=rule.verification, family=rule.family, cwe=rule.cwe or None, evidence=evidence))
        return out

    def analyze_project(self, ctx: ProjectContext):
        """Secret-bearing files that should not be in a repository."""
        out: list[Finding] = []
        names = [(f.rel, f) for f in ctx.files] + [(s["file"], None) for s in ctx.skipped]
        for rel, sf in names:
            if SECRET_FILE_NAMES.search(rel):
                out.append(Finding(
                    rule_id="SEC-SECRET-FILE", title="Credential/secret file present in repository",
                    category=CAT_SECURITY, subcategory="Secrets", severity="high", file=rel, line=None,
                    evidence=rel, explanation="A file that normally holds credentials or key material is part of the "
                    "scanned source tree.", impact="Committed secret files are exposed to every collaborator and "
                    "remain in git history.", remediation="Remove the file, add it to .gitignore, rotate any secrets "
                    "it contained and distribute them through a secrets manager.", confidence="medium",
                    source="custom-rules", verification="potential-risk", family="hardcoded-secret", cwe="CWE-798",
                    language=sf.lang_name if sf else None))
        return out


def _mask(text: str) -> str:
    """Never echo a full secret value into reports."""
    def repl(m: re.Match) -> str:
        v = m.group(0)
        return v[:4] + "…" + "*" * 4 if len(v) > 8 else v
    text = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAIza[0-9A-Za-z_\-]{35}\b|"
                  r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", repl, text)
    text = re.sub(r"""(?i)(\b\w*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|key)\w*["']?\s*[:=]\s*["'`])"""
                  r"""([^"'`\s]{4})([^"'`\s]*)(["'`])""",
                  lambda m: m.group(1) + m.group(2) + "…" + "*" * 4 + m.group(4), text)
    return text
