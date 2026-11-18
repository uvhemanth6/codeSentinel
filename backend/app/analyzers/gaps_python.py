"""Python coding-gap / loose-end detection (AST based)."""
from __future__ import annotations

import ast
import re

from ..models.finding import (CAT_GAPS, CAT_LOOSE, GAP_DEBUG, GAP_ERRORS, GAP_INCOMPLETE, GAP_VALIDATION,
                              V_HEURISTIC, V_POTENTIAL, V_STATIC)
from ..models.source import ProjectContext, SourceFile
from ..utils.functions import python_functions
from .base import Analyzer, build_finding, register
from .python_ast_security import dotted

ROUTE_DECOS = re.compile(r"(?:^|\.)(?:route|get|post|put|delete|patch|api_view|websocket)$")
HOOK_DOC = re.compile(r"(?i)override|hook|abstract|no-?op|subclass|intentionally|placeholder for subclass|interface")
BENIGN_EXC = {"ImportError", "ModuleNotFoundError", "StopIteration", "KeyboardInterrupt", "CancelledError",
              "ProcessLookupError", "StopAsyncIteration", "GeneratorExit", "BrokenPipeError", "FileNotFoundError",
              "NotImplementedError"}
STUB_VERBS = re.compile(r"^(?:process|handle|validate|verify|calculate|compute|save|send|update|delete|create|"
                        r"authenticate|authorize|check|is_valid|is_authorized|is_authenticated|has_permission|"
                        r"encrypt|decrypt|sanitize|parse|fetch|load|sync|upload|download|notify|charge|pay)")
SECURITY_STUB = re.compile(r"^(?:validate|verify|authenticate|authorize|check_|is_valid|is_authorized|"
                           r"is_authenticated|has_permission|sanitize|encrypt|decrypt)")
VALIDATION_SIGNS = re.compile(r"(?i)validat|schema|pydantic|marshmallow|\.load\(|abort\(|isinstance|assert|"
                              r"raise|\.isdigit\(|\.isnumeric\(|regex|re\.match|re\.fullmatch|\bif\b.*\bnot\b|"
                              r"wtforms|form\.validate|cerberus|jsonschema")


def _is_const_stub(stmt: ast.stmt) -> str | None:
    """Return a description when the statement returns a trivial constant."""
    if isinstance(stmt, ast.Return):
        v = stmt.value
        if v is None:
            return "returns nothing"
        if isinstance(v, ast.Constant) and (v.value is None or isinstance(v.value, (bool, int, float, str))):
            return f"returns constant {v.value!r}"
        if isinstance(v, (ast.Dict, ast.List, ast.Tuple, ast.Set)) and not getattr(v, "elts", getattr(v, "keys", [1])):
            return "returns an empty literal"
    return None


@register
class PythonGapsAnalyzer(Analyzer):
    name = "python-gaps"
    stage = "gaps"
    languages = ("Python",)

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        try:
            tree = ast.parse(sf.text)
        except (SyntaxError, ValueError) as e:
            return [build_finding(
                sf, rule_id="GAP-SYNTAX-ERROR", title="Python file does not parse", category=CAT_GAPS,
                subcategory="Maintainability Issues", severity="medium", line=getattr(e, "lineno", None) or 1,
                explanation=f"The file has a syntax error: {getattr(e, 'msg', e)}.",
                impact="The module cannot be imported; static analysis of this file is incomplete.",
                remediation="Fix the syntax error (or confirm the file targets a different Python version).",
                confidence="high", source="python-ast", verification=V_STATIC, family="syntax-error")]
        out = []
        parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        class_info = {n: self._class_flags(n) for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        funcs = python_functions(tree)

        for f in funcs:
            fn = f.node
            body = [s for s in fn.body]
            code = [s for s in body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                            and isinstance(s.value.value, (str, type(Ellipsis))))]
            doc = ast.get_docstring(fn) or ""
            decos = " ".join(f.decorators)
            cls = parents.get(fn)
            flags = class_info.get(cls, {}) if isinstance(cls, ast.ClassDef) else {}
            abstractish = ("abstractmethod" in decos or "overload" in decos or flags.get("abstract")
                           or flags.get("protocol") or HOOK_DOC.search(doc))
            is_route = any(ROUTE_DECOS.search(d) for d in f.decorators)
            dunder = f.name.startswith("__") and f.name.endswith("__")

            # --- empty / pass-only
            only_pass = all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                                       and s.value.value is Ellipsis) for s in code)
            if only_pass and not abstractish and not dunder and not (sf.is_test and f.name in ("setUp", "tearDown")):
                low_conf = bool(flags.get("has_bases"))
                out.append(build_finding(
                    sf, rule_id="GAP-EMPTY-FUNCTION", title=f"Empty implementation: `{f.name}`",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE,
                    severity="medium" if is_route else "low", line=f.start, end_line=f.end,
                    explanation=("The route handler" if is_route else "The function")
                    + " body is only `pass`/`...`, so it does nothing.",
                    impact="Callers get silent no-ops; features look finished but are not.",
                    remediation="Implement the behaviour, raise NotImplementedError deliberately, or remove it. "
                                "Mark abstract methods with @abstractmethod.",
                    confidence="low" if low_conf else "medium", source="python-ast",
                    verification=V_POTENTIAL if low_conf else V_STATIC, family="empty-function"))
            # --- NotImplementedError
            elif code and any(isinstance(s, ast.Raise) and self._raises(s, "NotImplementedError") for s in code[:2]) \
                    and len(code) <= 2 and not abstractish and not dunder:
                out.append(build_finding(
                    sf, rule_id="GAP-NOT-IMPLEMENTED", title=f"Unimplemented: `{f.name}` raises NotImplementedError",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="medium" if is_route else "low",
                    line=f.start, end_line=f.end,
                    explanation="The function immediately raises NotImplementedError outside an abstract base class.",
                    impact="Any call crashes at runtime; the feature is unfinished.",
                    remediation="Implement it, or declare the class/method abstract (ABC + @abstractmethod).",
                    confidence="medium", source="python-ast", verification=V_STATIC, family="not-implemented"))
            # --- placeholder return value
            elif len(code) == 1 and f.params >= 1 and not abstractish and not dunder:
                stub = _is_const_stub(code[0])
                if stub and STUB_VERBS.match(f.name.lstrip("_")) and not sf.is_test:
                    sec = bool(SECURITY_STUB.match(f.name.lstrip("_")))
                    out.append(build_finding(
                        sf, rule_id="GAP-PLACEHOLDER-RETURN", title=f"Placeholder implementation: `{f.name}` {stub}",
                        category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="high" if sec else "low",
                        line=f.start, end_line=f.end,
                        explanation=f"`{f.name}` takes arguments but its whole body {stub}.",
                        impact=("A stub that always succeeds in a security/validation function silently disables the "
                                "check." if sec else "Logic appears finished but returns a canned value."),
                        remediation="Implement the real logic or make the stub fail loudly until it exists.",
                        confidence="medium" if sec else "low", source="python-ast", verification=V_POTENTIAL,
                        family="placeholder-return"))
            # --- incomplete route
            if is_route and len(code) <= 1 and not only_pass and code and (_is_const_stub(code[0]) or (
                    isinstance(code[0], ast.Return) and isinstance(code[0].value, ast.Constant))):
                out.append(build_finding(
                    sf, rule_id="GAP-INCOMPLETE-API", title=f"API endpoint `{f.name}` returns a hard-coded value",
                    category=CAT_LOOSE, subcategory=GAP_INCOMPLETE, severity="medium", line=f.start, end_line=f.end,
                    explanation="The route handler only returns a constant and performs no work.",
                    impact="The endpoint is advertised but does not implement its contract.",
                    remediation="Implement the handler or remove the route until it is ready.", confidence="medium",
                    source="python-ast", verification=V_POTENTIAL, family="incomplete-api"))
            # --- validation gaps in request handlers
            if is_route:
                out += self._validation(sf, f, fn)

        out += self._handlers_and_calls(sf, tree, parents)
        out += self._debug(sf, tree, parents)
        return out

    # ------------------------------------------------------------------
    @staticmethod
    def _raises(node: ast.Raise, name: str) -> bool:
        exc = node.exc
        if isinstance(exc, ast.Call):
            exc = exc.func
        return isinstance(exc, ast.Name) and exc.id == name or (isinstance(exc, ast.Attribute) and exc.attr == name)

    @staticmethod
    def _class_flags(cls: ast.ClassDef) -> dict:
        bases = [ast.unparse(b) for b in cls.bases] + [ast.unparse(k.value) for k in cls.keywords]
        joined = " ".join(bases)
        return {"abstract": bool(re.search(r"ABC|ABCMeta|Protocol", joined)) or cls.name.startswith(("Base", "Abstract")),
                "protocol": "Protocol" in joined, "has_bases": bool(cls.bases)}

    def _validation(self, sf, f, fn):
        src = ast.get_source_segment(sf.text, fn) or ""
        uses_request = re.search(r"\brequest\.(args|form|json|values|data|files|get_json|cookies)\b|"
                                 r"request\.get_json\(", src)
        if not uses_request:
            return []
        if VALIDATION_SIGNS.search(src):
            return []
        # annotated pydantic/FastAPI parameters count as validation
        if any(a.annotation is not None for a in fn.args.args):
            return []
        return [build_finding(
            sf, rule_id="GAP-VALIDATION-HANDLER", title=f"Request data used without validation in `{f.name}`",
            category=CAT_GAPS, subcategory=GAP_VALIDATION, severity="medium", line=f.start, end_line=f.end,
            explanation="The handler reads request input but no checks, schema validation or error responses were "
                        "found in its body.",
            impact="Malformed or malicious input can crash the endpoint (500s) or reach downstream code unchecked.",
            remediation="Validate type, range and presence (e.g. pydantic/marshmallow/jsonschema) and return a 400 "
                        "response on failure.", confidence="low", source="python-ast", verification=V_POTENTIAL,
            family="missing-validation", tags=["heuristic"])]

    def _handlers_and_calls(self, sf, tree, parents):
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                body = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                                     and s.value.value is not Ellipsis)]
                swallow = all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(
                    s.value, ast.Constant)) for s in body)
                if not body:
                    swallow = True
                tname = ast.unparse(node.type) if node.type else ""
                last = tname.split(".")[-1]
                if swallow and last not in BENIGN_EXC:
                    broad = node.type is None or last in ("Exception", "BaseException")
                    out.append(build_finding(
                        sf, rule_id="GAP-EMPTY-EXCEPT",
                        title="Empty exception handler" + (" (bare except)" if node.type is None else ""),
                        category=CAT_GAPS, subcategory=GAP_ERRORS, severity="medium" if broad else "low",
                        line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno),
                        explanation=f"`except {tname or ''}` swallows the error without logging, re-raising or "
                                    "recovering.",
                        impact="Failures vanish silently, making bugs and security-relevant errors undetectable.",
                        remediation="Log the exception and handle it meaningfully, or catch a narrower exception "
                                    "and re-raise unknown ones.", confidence="high", source="python-ast",
                        verification=V_STATIC, family="empty-except"))
            elif isinstance(node, ast.Call):
                name = dotted(node.func)
                if re.fullmatch(r"requests\.(?:get|post|put|delete|head|patch|request)", name) and \
                        not any(k.arg == "timeout" or k.arg is None for k in node.keywords):
                    out.append(build_finding(
                        sf, rule_id="GAP-NO-TIMEOUT", title="HTTP request without timeout", category=CAT_GAPS,
                        subcategory=GAP_ERRORS, severity="low", line=node.lineno,
                        explanation=f"`{name}()` is called without `timeout=`; requests waits forever by default.",
                        impact="A stalled remote server can hang workers indefinitely (resource exhaustion).",
                        remediation="Pass an explicit timeout, e.g. `timeout=10`, and handle `requests.Timeout`.",
                        confidence="high", source="python-ast", verification=V_STATIC, family="missing-timeout"))
                if isinstance(node.func, ast.Name) and node.func.id in ("int", "float") and node.args:
                    seg = ast.get_source_segment(sf.text, node.args[0]) or ""
                    if re.search(r"\brequest\.(args|form|json|values|data|view_args)\b", seg) and not self._in_try(node, parents):
                        out.append(build_finding(
                            sf, rule_id="GAP-UNVALIDATED-CAST", title=f"`{node.func.id}()` on request data without error handling",
                            category=CAT_GAPS, subcategory=GAP_VALIDATION, severity="low", line=node.lineno,
                            explanation="User input is cast directly; invalid values raise ValueError/TypeError.",
                            impact="Bad input produces 500 errors instead of a clear 400 response.",
                            remediation="Wrap in try/except ValueError or validate with a schema first.",
                            confidence="medium", source="python-ast", verification=V_POTENTIAL,
                            family="missing-validation"))
        return out

    @staticmethod
    def _in_try(node, parents) -> bool:
        cur = node
        while cur in parents:
            cur = parents[cur]
            if isinstance(cur, ast.Try):
                return True
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
        return False

    def _debug(self, sf, tree, parents):
        out = []
        text = sf.text
        is_cli = bool(re.search(r"argparse|click|typer|import fire|sys\.argv|optparse|docopt", text)) or \
            re.search(r"(^|/)(cli|scripts?|bin|tools|examples?|demo|manage|__main__|migrations?)(/|\.py$)", sf.rel)
        prints: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            if name in ("breakpoint", "pdb.set_trace", "ipdb.set_trace", "pudb.set_trace", "set_trace"):
                out.append(build_finding(
                    sf, rule_id="DEBUG-BREAKPOINT", title="Debugger breakpoint left in code", category=CAT_LOOSE,
                    subcategory=GAP_DEBUG, severity="medium", line=node.lineno,
                    explanation=f"`{name}()` pauses execution in an interactive debugger.",
                    impact="In production this hangs the process (or exposes an interactive shell).",
                    remediation="Remove the breakpoint before merging.", confidence="high", source="python-ast",
                    verification=V_STATIC, family="debug-breakpoint"))
            elif name in ("print", "pprint.pprint", "pprint") and not is_cli and not sf.is_test:
                cur, skip = node, False
                while cur in parents:
                    cur = parents[cur]
                    if isinstance(cur, ast.If) and "__main__" in ast.dump(cur.test):
                        skip = True
                    if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)) and re.match(
                            r"(main|cli|run|show|display|report|print|dump|__repr__|__str__)", cur.name):
                        skip = True
                if not skip:
                    prints.append(node)
        if prints:
            first = prints[0]
            out.append(build_finding(
                sf, rule_id="DEBUG-PRINT", title=f"Debug print statements ({len(prints)})", category=CAT_LOOSE,
                subcategory=GAP_DEBUG, severity="low", line=first.lineno,
                explanation="`print()` is used in non-CLI application code, usually left over from debugging.",
                impact="Pollutes logs/stdout, can leak data and bypasses structured logging.",
                remediation="Use the `logging` module with appropriate levels.", confidence="medium",
                source="python-ast", verification=V_HEURISTIC, family="debug-print",
                occurrences=[{"line": p.lineno, "snippet": sf.lines[p.lineno - 1].strip()[:120]} for p in prints[:12]]))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                if any(m in ("pdb", "ipdb", "pudb") for m in mods):
                    out.append(build_finding(
                        sf, rule_id="DEBUG-IMPORT", title="Debugger module imported", category=CAT_LOOSE,
                        subcategory=GAP_DEBUG, severity="low", line=node.lineno,
                        explanation="A debugging module is imported in application code.",
                        impact="Indicates leftover debugging; may ship interactive debugging hooks.",
                        remediation="Remove the import.", confidence="high", source="python-ast",
                        verification=V_STATIC, family="debug-import"))
        return out
