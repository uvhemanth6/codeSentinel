"""Java / JavaScript / TypeScript coding gaps and loose ends (token-aware regex + brace matching)."""
from __future__ import annotations

import re

from ..models.finding import (CAT_GAPS, CAT_LOOSE, GAP_DEBUG, GAP_ERRORS, GAP_INCOMPLETE, GAP_VALIDATION,
                              V_HEURISTIC, V_POTENTIAL, V_STATIC)
from ..models.source import ProjectContext, SourceFile
from ..utils.functions import clike_functions
from .base import Analyzer, build_finding, register

JS_VALIDATORS = re.compile(r"\b(?:joi|zod|yup|express-validator|ajv|celebrate|class-validator|validator|"
                           r"check\(|body\(|param\(|query\(|validationResult|safeParse|\.validate\(|typeof\s|"
                           r"Number\.isInteger|Number\.isNaN|isNaN\(|Array\.isArray|\.length\s*[<>=!])")
STUB_NAME = re.compile(r"^(?:process|handle|validate|verify|calculate|compute|save|send|update|delete|create|"
                       r"authenticate|authorize|check|isValid|isAuthorized|isAuthenticated|hasPermission|encrypt|"
                       r"decrypt|sanitize|parse|sync|upload|download|notify|charge|pay)", re.I)
SEC_NAME = re.compile(r"^(?:validate|verify|authenticate|authorize|check|isValid|isAuthorized|isAuthenticated|"
                      r"hasPermission|sanitize|encrypt|decrypt)", re.I)
PLACEHOLDER_MSG = re.compile(r"(?i)not\s+(?:yet\s+)?implemented|todo|unimplemented|coming\s+soon|placeholder|"
                             r"not\s+supported\s+yet|stub")


def _line(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


@register
class CLikeGapsAnalyzer(Analyzer):
    name = "clike-gaps"
    stage = "gaps"
    languages = ("Java", "JavaScript", "TypeScript")

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        out = []
        blank = sf.blanked
        nocomment = sf.nocomment
        raw_lines = sf.lines
        is_java = sf.lang_name == "Java"
        funcs = clike_functions(sf)

        # ---- empty catch blocks / swallowed errors
        for m in re.finditer(r"\bcatch\s*(?:\([^)]*\))?\s*\{([^{}]*)\}", blank):
            inner = m.group(1).strip()
            ln = _line(blank, m.start())
            raw_inner = nocomment[m.start():m.end()]
            if inner == "":
                has_comment = bool(re.search(r"//|/\*", sf.text.split("\n")[ln - 1])) or any(
                    c_ln in range(ln, ln + 4) for c_ln, _ in sf.comments)
                out.append(build_finding(
                    sf, rule_id="GAP-EMPTY-CATCH", title="Empty catch block", category=CAT_GAPS,
                    subcategory=GAP_ERRORS, severity="low" if has_comment else "medium", line=ln,
                    explanation="The catch block does nothing: the exception is swallowed"
                                + (" (only a comment explains why)." if has_comment else "."),
                    impact="Errors disappear silently, hiding failures and security-relevant events.",
                    remediation="Log the error and recover/rethrow; if ignoring is intentional, log at debug level "
                                "and document why.", confidence="high", source="static-metrics",
                    verification=V_STATIC, family="empty-except"))
            elif re.fullmatch(r"(?:\w+\.printStackTrace\(\)\s*;?|console\.(?:log|error)\(\s*\w+\s*\)\s*;?)", inner):
                out.append(build_finding(
                    sf, rule_id="GAP-CATCH-PRINT-ONLY", title="Exception only printed, not handled",
                    category=CAT_GAPS, subcategory=GAP_ERRORS, severity="low", line=ln,
                    explanation="The catch block just prints the exception and continues.",
                    impact="Callers proceed with invalid state; errors go to stdout instead of a logger.",
                    remediation="Use a logger, handle the failure, or propagate it.", confidence="medium",
                    source="static-metrics", verification=V_HEURISTIC, family="empty-except"))
        for m in re.finditer(r"\.catch\(\s*(?:\(\s*\w*\s*\)|\w+|function\s*\(\s*\w*\s*\))\s*(?:=>\s*)?\{\s*\}\s*\)", blank):
            out.append(build_finding(
                sf, rule_id="GAP-EMPTY-CATCH", title="Promise rejection silently swallowed", category=CAT_GAPS,
                subcategory=GAP_ERRORS, severity="medium", line=_line(blank, m.start()),
                explanation="`.catch()` has an empty handler.",
                impact="Failed async operations vanish without a trace.",
                remediation="Handle or log the rejection.", confidence="high", source="static-metrics",
                verification=V_STATIC, family="empty-except"))

        # ---- empty functions, placeholders, not-implemented
        class_names = set(re.findall(r"\bclass\s+(\w+)", blank))
        for f in funcs:
            body = f.body_text
            inner = body.strip()[1:-1].strip() if len(body) >= 2 else ""
            k, annotations = f.start - 2, []
            while k >= 0 and raw_lines[k].strip().startswith("@"):
                annotations.append(raw_lines[k])
                k -= 1
            is_override = any("@Override" in a for a in annotations) or "override " in raw_lines[f.start - 1]
            is_ctor = f.name in class_names or f.name == "constructor"
            if inner == "" and not is_override and not is_ctor and f.name != "<anonymous>" and not f.name.startswith("<") and " " not in f.name and \
                    not re.search(r"\babstract\b|\binterface\b", raw_lines[f.start - 1]) and not sf.is_test and \
                    not re.match(r"^(?:set|on|noop|init|destroy|close|dispose|run|call|accept|apply|test)\b", f.name):
                out.append(build_finding(
                    sf, rule_id="GAP-EMPTY-FUNCTION", title=f"Empty function body: `{f.name}`", category=CAT_LOOSE,
                    subcategory=GAP_INCOMPLETE, severity="low", line=f.start, end_line=f.end,
                    explanation="The function/method has no statements.",
                    impact="Calls silently do nothing, which usually means the implementation was never written.",
                    remediation="Implement it, remove it, or document the intentional no-op.",
                    confidence="medium" if not is_java else "low", source="static-metrics", verification=V_POTENTIAL,
                    family="empty-function"))
                continue
            m = re.fullmatch(r"return\s*(null|undefined|0|false|true|\"\s*\"|''|\[\s*\]|\{\s*\}|new\s+\w+(?:<[^>]*>)?\(\s*\))?\s*;?", inner)
            if m and f.params >= 1 and STUB_NAME.match(f.name) and not is_override and not sf.is_test:
                sec = bool(SEC_NAME.match(f.name))
                out.append(build_finding(
                    sf, rule_id="GAP-PLACEHOLDER-RETURN", title=f"Placeholder implementation: `{f.name}` returns a constant",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="high" if sec else "low",
                    line=f.start, end_line=f.end,
                    explanation=f"`{f.name}` takes arguments but just `{inner}`.",
                    impact="A stub that always succeeds in a security-related function disables the check."
                           if sec else "Logic looks finished but returns a canned value.",
                    remediation="Implement the logic or fail loudly until it exists.", confidence="low",
                    source="static-metrics", verification=V_POTENTIAL, family="placeholder-return"))

        for m in re.finditer(r"throw\s+new\s+(\w*(?:NotImplemented|Unsupported\w*)\w*|Error)\s*\(([^)]*)\)", nocomment):
            exc, msg = m.group(1), m.group(2)
            if "NotImplemented" in exc or PLACEHOLDER_MSG.search(msg):
                out.append(build_finding(
                    sf, rule_id="GAP-NOT-IMPLEMENTED", title="Unimplemented code path throws placeholder error",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="medium", line=_line(nocomment, m.start()),
                    explanation=f"`{exc}` is thrown with a 'not implemented' style message.",
                    impact="This path crashes at runtime; the feature is unfinished.",
                    remediation="Implement it or remove the entry point.", confidence="high",
                    source="static-metrics", verification=V_STATIC, family="not-implemented"))

        # ---- incomplete API endpoints
        route = re.compile(r"""\b(?:app|router|server)\.(?:get|post|put|delete|patch|all)\(\s*(['"`])[^'"`]*\1\s*,\s*"""
                           r"""(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*\{\s*\}\s*\)""")
        for m in route.finditer(blank):
            out.append(build_finding(
                sf, rule_id="GAP-INCOMPLETE-API", title="API route handler has an empty body", category=CAT_LOOSE,
                subcategory=GAP_INCOMPLETE, severity="medium", line=_line(blank, m.start()),
                explanation="The route is registered but the handler never responds.",
                impact="Requests hang until the client times out.", remediation="Implement the handler and send a response.",
                confidence="high", source="static-metrics", verification=V_STATIC, family="incomplete-api"))
        for m in re.finditer(r"""res\.(?:status\(\s*501\s*\)\.)?(?:send|json)\(\s*(['"`])([^'"`]*)\1""", nocomment):
            if PLACEHOLDER_MSG.search(m.group(2)) or "status(501" in m.group(0).replace(" ", ""):
                out.append(build_finding(
                    sf, rule_id="GAP-INCOMPLETE-API", title="Endpoint returns a 'not implemented' placeholder",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="medium", line=_line(nocomment, m.start()),
                    explanation="The handler responds with placeholder text or HTTP 501.",
                    impact="The API advertises functionality that does not exist.",
                    remediation="Implement it or remove the route.", confidence="medium", source="static-metrics",
                    verification=V_STATIC, family="incomplete-api"))
        if is_java:
            for m in re.finditer(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping[^\n]*\n(?:\s*@[^\n]+\n)*\s*public\s+[\w<>\[\], ?]+\s+(\w+)\s*\([^)]*\)\s*(?:throws [\w, .]+)?\{\s*(return\s+(?:null|\"\"|\"[^\"]*\"|new \w+<?>?\(\))\s*;)?\s*\}", blank):
                out.append(build_finding(
                    sf, rule_id="GAP-INCOMPLETE-API", title=f"Controller method `{m.group(1)}` has no real implementation",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="medium",
                    line=_line(blank, m.start(1)),
                    explanation="A mapped endpoint is empty or just returns null/a constant.",
                    impact="Clients receive empty or canned responses.",
                    remediation="Implement the endpoint or remove the mapping.", confidence="medium",
                    source="static-metrics", verification=V_POTENTIAL, family="incomplete-api"))
            for m in re.finditer(r"@RequestBody\s+(?!@Valid|@Validated)(?:final\s+)?[\w<>\[\], ?]+\s+(\w+)", blank):
                if "@Valid" in blank[max(0, m.start() - 40): m.end()]:
                    continue
                out.append(build_finding(
                    sf, rule_id="GAP-VALIDATION-SPRING", title="@RequestBody parameter without @Valid",
                    category=CAT_GAPS, subcategory=GAP_VALIDATION, severity="medium", line=_line(blank, m.start()),
                    explanation=f"`{m.group(1)}` is bound from the request body without Bean Validation.",
                    impact="Missing/invalid fields reach business logic and the database unchecked.",
                    remediation="Annotate the parameter with @Valid and add constraints (@NotNull, @Size, ...) to the DTO.",
                    confidence="medium", source="static-metrics", verification=V_POTENTIAL, family="missing-validation"))
            for m in re.finditer(r"(?:Integer\.parseInt|Long\.parseLong|Double\.parseDouble)\(\s*[^)]*(?:getParameter|request\.|@RequestParam)[^)]*\)", blank):
                ln = _line(blank, m.start())
                if not self._in_try(blank, m.start()):
                    out.append(build_finding(
                        sf, rule_id="GAP-UNVALIDATED-CAST", title="Request value parsed without error handling",
                        category=CAT_GAPS, subcategory=GAP_VALIDATION, severity="low", line=ln,
                        explanation="Parsing user input can throw NumberFormatException which is not handled here.",
                        impact="Invalid input results in a 500 error.", remediation="Validate or catch NumberFormatException.",
                        confidence="medium", source="static-metrics", verification=V_POTENTIAL, family="missing-validation"))
        else:
            # Express/Node: handler reads request data but file never validates
            uses = [m for m in re.finditer(r"\breq\.(?:body|query|params)\b", blank)]
            if uses and not JS_VALIDATORS.search(blank) and not sf.is_test and re.search(r"\b(?:app|router)\.(?:get|post|put|delete|patch)\(", blank):
                m = uses[0]
                out.append(build_finding(
                    sf, rule_id="GAP-VALIDATION-EXPRESS", title=f"Request data used without validation ({len(uses)} uses)",
                    category=CAT_GAPS, subcategory=GAP_VALIDATION, severity="medium", line=_line(blank, m.start()),
                    explanation="Handlers read req.body/query/params but the file contains no validation library "
                                "or type/length checks.",
                    impact="Unexpected types and values reach business logic, queries and the file system.",
                    remediation="Validate input with zod/joi/express-validator and respond with 400 on failure.",
                    confidence="low", source="static-metrics", verification=V_POTENTIAL, family="missing-validation",
                    occurrences=[{"line": _line(blank, u.start()), "snippet": raw_lines[_line(blank, u.start()) - 1].strip()[:120]}
                                 for u in uses[:8]]))
            # network / parse calls with no error handling in their function
            for f in funcs:
                if sf.is_test:
                    break
                body = f.body_text
                if re.search(r"\btry\b|\.catch\(|catch\s*\(", body):
                    continue
                for m in re.finditer(r"\b(?:await\s+)?(?:fetch|axios(?:\.\w+)?)\s*\(|JSON\.parse\(|fs\.(?:readFileSync|writeFileSync|readFile)\(", body):
                    seg = m.group(0)
                    if "fetch" in seg or "axios" in seg:
                        if ".then(" in body and ".catch" not in body:
                            pass
                        title, sev = f"Network call without error handling in `{f.name}`", "low"
                    elif "JSON.parse" in seg:
                        title, sev = f"JSON.parse without error handling in `{f.name}`", "low"
                    else:
                        title, sev = f"File I/O without error handling in `{f.name}`", "low"
                    ln = f.start + body.count("\n", 0, m.start())
                    out.append(build_finding(
                        sf, rule_id="GAP-NO-ERROR-HANDLING", title=title, category=CAT_GAPS, subcategory=GAP_ERRORS,
                        severity=sev, line=ln,
                        explanation="The enclosing function has no try/catch or .catch() around an operation that can fail.",
                        impact="Rejections/exceptions surface as unhandled errors or crashed requests.",
                        remediation="Wrap in try/catch (or add .catch) and return a controlled error.",
                        confidence="low", source="static-metrics", verification=V_POTENTIAL, family="no-error-handling"))
                    break

        # ---- debug leftovers
        out += self._debug(sf, blank, is_java, raw_lines)
        return out

    @staticmethod
    def _in_try(text: str, idx: int) -> bool:
        before = text[max(0, idx - 400): idx]
        return before.rfind("try") > before.rfind("}") and "try" in before

    def _debug(self, sf, blank, is_java, raw_lines):
        out = []
        if sf.is_test or re.search(r"(^|/)(scripts?|bin|tools|cli)/|\.config\.|webpack|gulpfile|Gruntfile", sf.rel):
            return out
        pat = (r"System\.(?:out|err)\.print(?:ln|f)?\s*\(|\.printStackTrace\s*\(" if is_java
               else r"\bconsole\.(?:log|debug|info|trace|dir|table)\s*\(")
        hits = [m for m in re.finditer(pat, blank)]
        # a Java main method / CLI may legitimately print
        if is_java and re.search(r"public\s+static\s+void\s+main\s*\(", blank):
            hits = [] if len(hits) < 4 else hits
        if hits:
            first = _line(blank, hits[0].start())
            out.append(build_finding(
                sf, rule_id="DEBUG-CONSOLE", title=f"Debug output statements ({len(hits)})", category=CAT_LOOSE,
                subcategory=GAP_DEBUG, severity="low", line=first,
                explanation=("System.out/printStackTrace" if is_java else "console.log-style calls")
                + " are used in application code.",
                impact="Unstructured output pollutes logs, may leak data and bypasses log levels.",
                remediation="Use a logging framework (SLF4J/Logback, pino/winston) with levels.", confidence="medium",
                source="static-metrics", verification=V_HEURISTIC, family="debug-print",
                occurrences=[{"line": _line(blank, h.start()), "snippet": raw_lines[_line(blank, h.start()) - 1].strip()[:120]}
                             for h in hits[:12]]))
        if not is_java:
            for m in re.finditer(r"^\s*debugger\s*;?\s*$", blank, re.M):
                out.append(build_finding(
                    sf, rule_id="DEBUG-BREAKPOINT", title="`debugger` statement left in code", category=CAT_LOOSE,
                    subcategory=GAP_DEBUG, severity="medium", line=_line(blank, m.start()),
                    explanation="A `debugger` statement pauses execution when dev tools are open.",
                    impact="Halts execution in browsers and shows unfinished work.",
                    remediation="Remove the statement.", confidence="high", source="static-metrics",
                    verification=V_STATIC, family="debug-breakpoint"))
        return out
