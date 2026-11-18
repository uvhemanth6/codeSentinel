"""Loose ends: TODO/FIXME/XXX/HACK markers and hard-coded development settings (all languages)."""
from __future__ import annotations

import re

from ..models.finding import CAT_GAPS, CAT_LOOSE, GAP_CONFIG, GAP_INCOMPLETE, V_HEURISTIC, V_POTENTIAL, V_STATIC
from ..models.source import ProjectContext, SourceFile
from .base import Analyzer, build_finding, register

MARKER = re.compile(r"(?:^|[\s:(\[*/#-])(TODO|FIXME|XXX|HACK)(?=\s*[:(\-!]|\s+\w|\s*$)|\b(?i:todo)\s*[:(]")
SECURITY_WORDS = re.compile(r"(?i)auth|password|secur|encrypt|sanitiz|validat|permission|csrf|xss|inject|token|"
                            r"vulnerab|crypto|secret|escape|rate.?limit|access control")
MAX_PER_FILE = 20


@register
class MarkerAnalyzer(Analyzer):
    name = "loose-end-markers"
    stage = "loose_ends"

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        if sf.lang_name == "JSON":
            return []
        out = []
        count = 0
        for ln, text in sf.comments:
            for offset, sub in enumerate(text.split("\n")):
                m = MARKER.search(sub)
                if not m:
                    continue
                kind = (m.group(1) or "TODO").upper()
                line_no = ln + offset
                sec = bool(SECURITY_WORDS.search(sub))
                sev = "medium" if sec or kind in ("FIXME", "HACK") else "low"
                if kind == "XXX" and not sec:
                    sev = "low"
                count += 1
                if count > MAX_PER_FILE:
                    break
                msg = re.sub(r"^[\s#/*<!\-]+", "", sub).strip()
                out.append(build_finding(
                    sf, rule_id=f"LOOSE-{kind}", title=f"{kind} marker: {msg[:70]}", category=CAT_LOOSE,
                    subcategory=GAP_INCOMPLETE, severity=sev, line=line_no,
                    explanation=f"A {kind} comment marks unfinished or questionable work"
                                + (" in a security-relevant area." if sec else "."),
                    impact="Known gaps ship to production; HACK/FIXME markers often hide fragile workarounds."
                           if kind != "TODO" else "Planned work is untracked and may be forgotten.",
                    remediation="Resolve it, or convert it to a tracked issue and remove the marker.",
                    confidence="high", source="comment-scan", verification=V_STATIC, family=f"marker-{kind.lower()}",
                    evidence=sf.lines[line_no - 1].strip() if line_no <= len(sf.lines) else msg,
                    tags=["security-relevant"] if sec else []))
            if count > MAX_PER_FILE:
                out.append(build_finding(
                    sf, rule_id="LOOSE-MARKERS-MORE", title=f"More than {MAX_PER_FILE} TODO/FIXME markers in this file",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="low", line=1,
                    explanation="Only the first markers are listed individually.", impact="Large backlog in one file.",
                    remediation="Triage the markers.", confidence="high", source="comment-scan", verification=V_STATIC,
                    family="marker-overflow", evidence=sf.lines[0] if sf.lines else ""))
                break
        return out


DEV_RULES = [
    ("DEV-DEBUG-TRUE", "Debug mode enabled in configuration", "debug-enabled", "medium",
     r"""^\s*(?:DEBUG|debug|FLASK_DEBUG|APP_DEBUG)\s*[:=]\s*(?:True|true|1|["']1["']|["']true["'])\s*[,;]?\s*(?:#.*)?$""",
     ("Python", "Properties", "YAML", "JavaScript", "TypeScript", "JSON"),
     "Debug features (verbose errors, debuggers, reloaders) are switched on by a hard-coded value.",
     "Debug mode leaks stack traces/configuration and can expose interactive consoles in production.",
     "Drive debug from the environment and default to off."),
    ("DEV-LOCALHOST", "Hard-coded localhost URL", "hardcoded-localhost", "low",
     r"""["'`]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^"'`\s]*["'`]""",
     ("Python", "Java", "JavaScript", "TypeScript", "Go", "C#", "Kotlin", "PHP", "Ruby"),
     "A development URL is hard-coded in application code.",
     "The code breaks (or talks to the wrong host) once deployed elsewhere.",
     "Read service URLs from configuration/environment variables."),
    ("DEV-NODE-ENV", "Environment hard-coded to development", "hardcoded-env", "low",
     r"""NODE_ENV\s*[=:]\s*["']?development["']?|spring\.profiles\.active\s*=\s*dev|FLASK_ENV\s*=\s*development""",
     None, "A development environment flag is committed to configuration.",
     "Production builds may run with development behaviour.", "Set the environment at deploy time."),
    ("DEV-SQL-LOG", "SQL/DDL auto-management or verbose DB logging enabled", "dev-database-settings", "medium",
     r"""spring\.jpa\.hibernate\.ddl-auto\s*[=:]\s*(?:create|create-drop|update)|spring\.jpa\.show-sql\s*[=:]\s*true|"""
     r"""\bddl-auto:\s*(?:create|create-drop|update)\b|show-sql:\s*true|spring\.h2\.console\.enabled\s*[=:]\s*true|"""
     r"""\bsynchronize\s*:\s*true""",
     None, "Schema auto-generation or SQL logging is enabled in committed configuration.",
     "Schema can be altered/dropped on startup and SQL (with data) lands in logs.",
     "Use migrations (Flyway/Liquibase) and profile-specific dev-only settings."),
    ("DEV-ACTUATOR", "Management endpoints fully exposed", "dev-management-exposed", "high",
     r"""management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*|include:\s*["']?\*["']?""",
     ("Properties", "YAML"), "All Spring Boot Actuator endpoints are exposed over HTTP.",
     "Endpoints such as /env, /heapdump or /shutdown leak secrets or allow takeover.",
     "Expose only health/info and protect the rest with authentication."),
    ("DEV-TEST-FLAG", "Test/mock mode flag hard-coded on", "hardcoded-test-mode", "low",
     r"""\b(?:MOCK_MODE|USE_MOCK|TESTING|DEV_MODE|BYPASS_AUTH|SKIP_AUTH|DISABLE_AUTH|DISABLE_SSL)\s*[:=]\s*(?:True|true|1)\b""",
     None, "A development/mock/bypass switch is enabled by a literal.",
     "Authentication or real integrations may be skipped in production.",
     "Gate dev switches behind environment configuration, default off."),
]


@register
class DevSettingsAnalyzer(Analyzer):
    name = "dev-settings"
    stage = "loose_ends"

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        if sf.is_test or sf.is_example:
            return []
        out = []
        lines = sf.nocomment.split("\n")
        for rule_id, title, fam, sev, pat, langs, expl, impact, fix in DEV_RULES:
            if langs and sf.lang_name not in langs:
                continue
            rx = re.compile(pat, re.M)
            for idx, line in enumerate(lines):
                if len(line) > 600 or not rx.search(line):
                    continue
                out.append(build_finding(
                    sf, rule_id=rule_id, title=title, category=CAT_GAPS, subcategory=GAP_CONFIG, severity=sev,
                    line=idx + 1, explanation=expl, impact=impact, remediation=fix, confidence="medium",
                    source="custom-rules", verification=V_POTENTIAL, family=fam))
                break  # one per rule per file is enough
        return out
