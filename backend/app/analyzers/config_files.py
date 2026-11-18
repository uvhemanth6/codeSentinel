"""Language-specific analyzers for JSON, YAML, SQL, HTML, CSS and Docker/config files."""
from __future__ import annotations

import json
import re

from ..models.finding import (CAT_GAPS, CAT_LOOSE, CAT_SECURITY, CAT_SLOP, GAP_CONFIG, GAP_MAINT, GAP_VALIDATION,
                              V_HEURISTIC, V_POTENTIAL, V_STATIC)
from ..models.source import ProjectContext, SourceFile
from .base import Analyzer, build_finding, register

JSONC = re.compile(r"(?:tsconfig|jsconfig|\.eslintrc|\.babelrc|devcontainer|settings|launch|tasks|extensions)[^/]*$|\.vscode/",
                   re.I)


def _ln(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


@register
class JsonAnalyzer(Analyzer):
    name = "json-config"
    stage = "gaps"
    languages = ("JSON",)

    def analyze_file(self, sf, ctx):
        out = []
        try:
            data = json.loads(sf.text)
        except ValueError as e:
            if JSONC.search(sf.rel) or not sf.text.strip():
                return []
            return [build_finding(
                sf, rule_id="CFG-JSON-INVALID", title="Invalid JSON file", category=CAT_GAPS, subcategory=GAP_CONFIG,
                severity="medium", line=getattr(e, "lineno", 1),
                explanation=f"The file does not parse as JSON: {e}.", impact="Tools that load this file will fail.",
                remediation="Fix the syntax error.", confidence="high", source="json-parser", verification=V_STATIC,
                family="invalid-config")]
        if sf.rel.endswith("package.json") and isinstance(data, dict):
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    if isinstance(ver, str) and (ver.strip() in ("*", "latest", "") or ver.startswith(("git+http://", "http://"))):
                        ln = next((i for i, l in enumerate(sf.lines, 1) if f'"{name}"' in l), 1)
                        out.append(build_finding(
                            sf, rule_id="CFG-UNPINNED-DEP", title=f"Unpinned dependency `{name}` ({ver or 'empty'})",
                            category=CAT_GAPS, subcategory=GAP_CONFIG, severity="medium", line=ln,
                            explanation="The version range accepts any release (or an insecure source).",
                            impact="Builds are not reproducible and a malicious/breaking release is pulled automatically.",
                            remediation="Pin to a compatible semver range and commit the lockfile.", confidence="high",
                            source="json-parser", verification=V_STATIC, family="unpinned-dependency", tags=["supply-chain"]))
            for name, script in (data.get("scripts") or {}).items():
                if isinstance(script, str) and re.search(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", script):
                    ln = next((i for i, l in enumerate(sf.lines, 1) if f'"{name}"' in l), 1)
                    out.append(build_finding(
                        sf, rule_id="SEC-PIPE-SHELL", title="npm script pipes a download into a shell",
                        category=CAT_SECURITY, subcategory="Dangerous Functions", severity="medium", line=ln,
                        explanation="A script downloads and executes remote code.",
                        impact="Compromised remote content runs on developer/CI machines.",
                        remediation="Pin and verify the download.", confidence="high", source="json-parser",
                        verification=V_STATIC, family="dangerous-function", cwe="CWE-494"))
            if "license" not in data and not data.get("private"):
                out.append(build_finding(
                    sf, rule_id="CFG-NO-LICENSE", title="package.json has no license field", category=CAT_GAPS,
                    subcategory=GAP_MAINT, severity="info", line=1,
                    explanation="No `license` is declared for a non-private package.", impact="Consumers cannot tell usage terms.",
                    remediation="Add a license (or set `private: true`).", confidence="high", source="json-parser",
                    verification=V_STATIC, family="missing-license", evidence=sf.lines[0] if sf.lines else "{"))
        return out


@register
class YamlAnalyzer(Analyzer):
    name = "yaml-config"
    stage = "gaps"
    languages = ("YAML",)

    RULES = [
        ("CFG-YAML-PRIVILEGED", "Container runs privileged / as root", r"^\s*(?:privileged:\s*true|runAsUser:\s*0\b|"
         r"allowPrivilegeEscalation:\s*true|hostNetwork:\s*true|hostPID:\s*true)", "high", CAT_SECURITY, "Configuration",
         "The workload is granted elevated host privileges.", "A container escape or compromise gives control of the host.",
         "Drop privileges: run as non-root, disable privileged mode and privilege escalation.", "privileged-container"),
        ("CFG-YAML-LATEST", "Container image uses the `latest` tag", r"^\s*-?\s*image:\s*['\"]?[\w./-]+(?::latest)?['\"]?\s*$",
         "low", CAT_GAPS, GAP_CONFIG, "Image tag is `latest` or missing.", "Deployments are not reproducible and may pull unreviewed images.",
         "Pin images to a version or digest.", "unpinned-image"),
        ("CFG-YAML-WRITEALL", "GitHub Actions workflow grants write-all permissions", r"permissions:\s*write-all", "high",
         CAT_SECURITY, "Configuration", "The workflow token has write access to everything.",
         "A compromised step can modify code, releases and secrets.", "Grant least-privilege `permissions:` per job.",
         "excess-permissions"),
        ("CFG-YAML-HTTP", "Plain-HTTP endpoint in configuration", r"https?://(?!localhost|127\.|.*example)\S+",
         "low", CAT_SECURITY, "Transport Security", "", "", "", "insecure-http"),
    ]

    def analyze_file(self, sf, ctx):
        out = []
        for i, line in enumerate(sf.lines, 1):
            if line.startswith("\t") or re.match(r"^ *\t", line):
                out.append(build_finding(
                    sf, rule_id="CFG-YAML-TAB", title="Tab indentation in YAML", category=CAT_GAPS, subcategory=GAP_CONFIG,
                    severity="medium", line=i, explanation="YAML forbids tab characters for indentation.",
                    impact="The file fails to parse in most YAML loaders.", remediation="Indent with spaces.",
                    confidence="high", source="yaml-scan", verification=V_STATIC, family="invalid-config"))
                break
        nc = sf.nocomment.split("\n")
        for rid, title, pat, sev, cat, sub, expl, impact, fix, fam in self.RULES:
            if rid == "CFG-YAML-HTTP":
                continue
            rx = re.compile(pat)
            for i, line in enumerate(nc, 1):
                if not rx.search(line):
                    continue
                if rid == "CFG-YAML-LATEST":
                    mm = re.search(r"image:\s*['\"]?([\w./-]+)(?::([\w.-]+))?", line)
                    if not mm or (mm.group(2) and mm.group(2) != "latest") or "${" in line or "@sha256" in line:
                        continue
                out.append(build_finding(
                    sf, rule_id=rid, title=title, category=cat, subcategory=sub, severity=sev, line=i,
                    explanation=expl, impact=impact, remediation=fix, confidence="medium", source="yaml-scan",
                    verification=V_POTENTIAL, family=fam))
        return out


@register
class SqlAnalyzer(Analyzer):
    name = "sql-scripts"
    stage = "gaps"
    languages = ("SQL",)

    def analyze_file(self, sf, ctx):
        out = []
        text = sf.nocomment
        for m in re.finditer(r"(?is)\b(DELETE\s+FROM\s+\w+|UPDATE\s+\w+\s+SET\s+[^;]*?)(?=;|$)", text):
            stmt = m.group(0)
            if not re.search(r"(?i)\bWHERE\b", stmt):
                kind = "DELETE" if stmt.upper().startswith("DELETE") else "UPDATE"
                out.append(build_finding(
                    sf, rule_id="SQL-NO-WHERE", title=f"{kind} statement without WHERE clause", category=CAT_GAPS,
                    subcategory=GAP_VALIDATION, severity="high", line=_ln(text, m.start()),
                    explanation=f"This {kind} affects every row in the table.", impact="Accidental mass data loss/corruption.",
                    remediation="Add a WHERE clause (or confirm a full-table change is intended and document it).",
                    confidence="medium", source="sql-scan", verification=V_POTENTIAL, family="sql-no-where",
                    evidence=re.sub(r"\s+", " ", stmt)[:200]))
        for m in re.finditer(r"(?i)\bGRANT\s+ALL\b[^;]*|\bIDENTIFIED\s+BY\s+'[^']+'|\bPASSWORD\s*(?:=|\()\s*'[^']+'", text):
            out.append(build_finding(
                sf, rule_id="SQL-PRIVILEGE-CREDS", title="Over-broad grant or inline credential in SQL",
                category=CAT_SECURITY, subcategory="Access Control", severity="high" if "GRANT" in m.group(0).upper() else "medium",
                line=_ln(text, m.start()), explanation="The script grants all privileges or embeds a password literal.",
                impact="Excess privileges and committed passwords widen the blast radius of a breach.",
                remediation="Grant only required privileges and supply passwords via secrets management.",
                confidence="medium", source="sql-scan", verification=V_POTENTIAL, family="hardcoded-secret",
                cwe="CWE-250", evidence=re.sub(r"'[^']+'", "'****'", m.group(0))[:200]))
        for m in re.finditer(r"(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.`\"\[\]]+)\s*\((.*?)\)\s*(?:ENGINE|;|$)", text):
            if not re.search(r"(?i)PRIMARY\s+KEY", m.group(2)):
                out.append(build_finding(
                    sf, rule_id="SQL-NO-PK", title=f"Table {m.group(1)} has no primary key", category=CAT_GAPS,
                    subcategory=GAP_MAINT, severity="low", line=_ln(text, m.start()),
                    explanation="CREATE TABLE defines no PRIMARY KEY.", impact="Duplicate rows, poor replication and slow updates.",
                    remediation="Add a primary key.", confidence="medium", source="sql-scan", verification=V_POTENTIAL,
                    family="sql-no-pk"))
        for m in re.finditer(r"(?i)\bSELECT\s+\*\s+FROM", text):
            out.append(build_finding(
                sf, rule_id="SQL-SELECT-STAR", title="SELECT * used", category=CAT_SLOP, subcategory="Boilerplate",
                severity="info", line=_ln(text, m.start()), explanation="`SELECT *` fetches all columns.",
                impact="Breaks when schema changes and over-fetches data.", remediation="List the needed columns.",
                confidence="high", source="sql-scan", verification=V_HEURISTIC, family="select-star"))
            break
        return out


@register
class HtmlAnalyzer(Analyzer):
    name = "html-markup"
    stage = "gaps"
    languages = ("HTML",)

    def analyze_file(self, sf, ctx):
        text = sf.nocomment
        out = []

        def add(rid, title, sev, idx, expl, impact, fix, cat=CAT_SECURITY, sub="Transport Security", fam=None, conf="high", cwe=None):
            out.append(build_finding(
                sf, rule_id=rid, title=title, category=cat, subcategory=sub, severity=sev, line=_ln(text, idx),
                explanation=expl, impact=impact, remediation=fix, confidence=conf, source="html-scan",
                verification=V_STATIC, family=fam or rid.lower(), cwe=cwe))
        for m in re.finditer(r"(?is)<a\b[^>]*\btarget\s*=\s*[\"']?_blank[\"']?[^>]*>", text):
            if not re.search(r"(?i)rel\s*=\s*[\"'][^\"']*noopener", m.group(0)):
                add("HTML-BLANK-NOOPENER", "target=_blank without rel=noopener", "low", m.start(),
                    "The linked page can access `window.opener`.", "Reverse tabnabbing: the opened page can redirect the original tab.",
                    'Add rel="noopener noreferrer".', sub="Access Control", cwe="CWE-1022")
        for m in re.finditer(r"(?is)<(?:script|link)\b[^>]*(?:src|href)\s*=\s*[\"']http://[^\"']+[\"'][^>]*>", text):
            add("HTML-HTTP-RESOURCE", "Script/stylesheet loaded over plain HTTP", "high", m.start(),
                "A resource is fetched without TLS.", "Attackers on the network can inject code into the page.",
                "Load over https:// and add Subresource Integrity (integrity=...).", cwe="CWE-319")
        for m in re.finditer(r"(?is)<script\b[^>]*src\s*=\s*[\"']https://(?:cdn|unpkg|cdnjs)[^\"']+[\"'][^>]*>", text):
            if "integrity" not in m.group(0).lower():
                add("HTML-NO-SRI", "CDN script without Subresource Integrity", "low", m.start(),
                    "A third-party script has no integrity hash.", "A compromised CDN could serve malicious code.",
                    'Add integrity="sha384-..." and crossorigin="anonymous".', sub="Supply Chain", conf="medium", cwe="CWE-353")
        for m in re.finditer(r"(?is)<form\b[^>]*action\s*=\s*[\"']http://[^\"']+[\"'][^>]*>", text):
            add("HTML-FORM-HTTP", "Form submits over plain HTTP", "high", m.start(),
                "The form action uses http://.", "Submitted data (possibly credentials) is sent in clear text.",
                "Use https:// for form targets.", cwe="CWE-319")
        for m in re.finditer(r"(?is)<form\b(?=[^>]*\bmethod\s*=\s*[\"']?get)[^>]*>.*?type\s*=\s*[\"']password", text):
            add("HTML-PASSWORD-GET", "Password field in a GET form", "high", m.start(),
                "Credentials would be placed in the URL.", "URLs end up in history, logs and referrers.",
                'Use method="post".', sub="Sensitive Data Exposure", cwe="CWE-598")
        for m in re.finditer(r"(?is)<iframe\b(?![^>]*\bsandbox)[^>]*>", text):
            add("HTML-IFRAME-SANDBOX", "iframe without sandbox attribute", "low", m.start(),
                "Embedded content runs with full privileges of its origin.", "Clickjacking / content injection risk.",
                "Add a restrictive sandbox attribute.", conf="medium", cwe="CWE-1021")
        for m in re.finditer(r"(?is)<img\b(?![^>]*\balt\s*=)[^>]*>", text):
            add("HTML-IMG-ALT", "Image without alt text", "info", m.start(), "The <img> has no alt attribute.",
                "Inaccessible to screen readers.", "Add meaningful alt text (or alt=\"\" for decorative images).",
                cat=CAT_GAPS, sub=GAP_MAINT, fam="html-img-alt")
            break
        for m in re.finditer(r"(?is)\son(?:click|load|error|mouseover)\s*=\s*[\"'][^\"']*(?:eval|document\.write|innerHTML)", text):
            add("HTML-INLINE-HANDLER", "Inline event handler with dangerous sink", "medium", m.start(),
                "An inline handler uses eval/innerHTML/document.write.", "Hard to protect with CSP; XSS risk.",
                "Move logic to scripts and avoid dangerous sinks.", sub="Cross-Site Scripting", conf="medium",
                fam="xss", cwe="CWE-79")
        if re.search(r"(?i)<html", text) and not re.search(r"(?i)<title>", text) and not sf.rel.endswith(".vue"):
            out.append(build_finding(
                sf, rule_id="HTML-NO-TITLE", title="HTML document has no <title>", category=CAT_GAPS,
                subcategory=GAP_MAINT, severity="info", line=1, explanation="The page lacks a title element.",
                impact="Poor accessibility and SEO.", remediation="Add a descriptive <title>.", confidence="high",
                source="html-scan", verification=V_STATIC, family="html-no-title", evidence=sf.lines[0] if sf.lines else ""))
        return out


@register
class CssAnalyzer(Analyzer):
    name = "css-styles"
    stage = "slop"
    languages = ("CSS",)

    def analyze_file(self, sf, ctx):
        out = []
        text = sf.nocomment
        n = len(re.findall(r"!important", text))
        if n > 10:
            m = re.search(r"!important", text)
            out.append(build_finding(
                sf, rule_id="CSS-IMPORTANT", title=f"`!important` used {n} times", category=CAT_SLOP,
                subcategory="Complexity", severity="low", line=_ln(text, m.start()),
                explanation="Heavy use of !important signals specificity battles.", impact="Styles become hard to override and maintain.",
                remediation="Refactor selectors/specificity.", confidence="high", source="css-scan",
                verification=V_HEURISTIC, family="css-important"))
        for m in re.finditer(r"[^{}\n][^{}]*\{\s*\}", text):
            out.append(build_finding(
                sf, rule_id="CSS-EMPTY-RULE", title="Empty CSS rule", category=CAT_LOOSE, subcategory="Incomplete Implementation",
                severity="info", line=_ln(text, m.start()), explanation="A selector has an empty declaration block.",
                impact="Dead styles / unfinished work.", remediation="Remove or complete the rule.", confidence="high",
                source="css-scan", verification=V_STATIC, family="css-empty-rule"))
            break
        for m in re.finditer(r"""@import\s+(?:url\()?["']?http://""", text):
            out.append(build_finding(
                sf, rule_id="CSS-HTTP-IMPORT", title="Stylesheet imported over plain HTTP", category=CAT_SECURITY,
                subcategory="Transport Security", severity="medium", line=_ln(text, m.start()),
                explanation="@import fetches CSS over http://.", impact="Network attackers can inject styles (UI redress/data exfiltration).",
                remediation="Use https://.", confidence="high", source="css-scan", verification=V_STATIC,
                family="insecure-http", cwe="CWE-319"))
        return out


@register
class DockerAnalyzer(Analyzer):
    name = "dockerfile"
    stage = "gaps"
    languages = ("Dockerfile",)

    def analyze_file(self, sf, ctx):
        out = []
        text = sf.nocomment
        if not re.search(r"(?im)^\s*USER\s+(?!root\b)\S+", text):
            out.append(build_finding(
                sf, rule_id="DOCKER-ROOT", title="Container runs as root", category=CAT_SECURITY,
                subcategory="Configuration", severity="medium", line=1,
                explanation="The Dockerfile never switches to a non-root USER.", impact="A compromise of the app gives root in the container.",
                remediation="Add a dedicated unprivileged USER.", confidence="medium", source="docker-scan",
                verification=V_POTENTIAL, family="container-root", evidence=sf.lines[0] if sf.lines else "FROM"))
        for m in re.finditer(r"(?im)^\s*FROM\s+(\S+)\s*$", text):
            img = m.group(1)
            if img.endswith(":latest") or (":" not in img and "@" not in img and img.lower() != "scratch"):
                out.append(build_finding(
                    sf, rule_id="CFG-DOCKER-LATEST", title=f"Base image `{img}` is not pinned", category=CAT_GAPS,
                    subcategory=GAP_CONFIG, severity="low", line=_ln(text, m.start()),
                    explanation="The base image uses `latest` or no tag.", impact="Builds are not reproducible.",
                    remediation="Pin a version or digest.", confidence="high", source="docker-scan",
                    verification=V_STATIC, family="unpinned-image"))
        for m in re.finditer(r"(?im)^\s*ADD\s+https?://", text):
            out.append(build_finding(
                sf, rule_id="DOCKER-ADD-URL", title="ADD fetches a remote URL", category=CAT_SECURITY,
                subcategory="Supply Chain", severity="low", line=_ln(text, m.start()),
                explanation="`ADD <url>` downloads without verification.", impact="Tampered downloads enter the image.",
                remediation="Use curl/wget with checksum verification.", confidence="medium", source="docker-scan",
                verification=V_STATIC, family="remote-add"))
        return out
