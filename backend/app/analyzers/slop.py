"""Code-slop analyzer: measurable low-quality patterns (never guesses authorship)."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from collections import defaultdict

from ..models.finding import CAT_SLOP, V_HEURISTIC, V_POTENTIAL, V_STATIC, Finding
from ..models.source import ProjectContext, SourceFile
from ..utils.functions import FuncInfo, get_functions
from .base import Analyzer, build_finding, register

SUB_COMPLEXITY, SUB_DUP, SUB_DEAD, SUB_NAMING = "Complexity", "Duplication", "Dead Code", "Naming"
SUB_BOILER, SUB_DEPS, SUB_EXC, SUB_COMMENTS, SUB_ABS = ("Boilerplate", "Dependencies", "Exception Handling",
                                                         "Comments", "Unnecessary Abstraction")
SUB_UNUSED = "Unused Code"

BAD_NAMES = re.compile(r"^(?:foo|bar|baz|qux|temp\d*|tmp\d*|data\d+|var\d+|val\d+|thing\d*|stuff\d*|obj\d+|"
                       r"res\d+|result\d+|test\d+|asdf\w*|xxx+|aaa+|my_?var|new_?var|do_?stuff|do_?it|handle_?it|"
                       r"process_?data|func\d+|method\d+|helper\d+)$", re.I)
ALLOWED_SHORT = {"i", "j", "k", "n", "m", "x", "y", "z", "e", "f", "s", "t", "a", "b", "c", "d", "p", "q", "v", "w",
                 "r", "_", "id", "fn", "cb", "db", "io", "ok", "df", "np", "pd", "ax", "fp", "pk", "ws", "el", "tx",
                 "rx", "dx", "dy", "T", "U", "K", "V", "$", "$$"}


def _fn_severity(length: int, t: dict) -> str | None:
    if length > t["very_long_function_lines"]:
        return "medium"
    if length > t["long_function_lines"]:
        return "low"
    return None


@register
class SlopFunctionAnalyzer(Analyzer):
    """Per-file structural metrics: long functions, nesting, complexity, parameters, naming, dead code."""
    name = "slop-functions"
    stage = "slop"
    languages = ("Python", "Java", "JavaScript", "TypeScript")

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        t = ctx.threshold
        out: list[Finding] = []
        tree = None
        if sf.lang_name == "Python":
            try:
                tree = ast.parse(sf.text)
            except (SyntaxError, ValueError):
                return []
        funcs = get_functions(sf, tree)
        for f in funcs:
            sev = _fn_severity(f.length, t)
            if sev and not sf.is_test:
                out.append(build_finding(
                    sf, rule_id="SLOP-LONG-FUNCTION", title=f"Long function `{f.name}` ({f.length} lines)",
                    category=CAT_SLOP, subcategory=SUB_COMPLEXITY, severity=sev, line=f.start, end_line=f.end,
                    explanation=f"`{f.name}` spans {f.length} lines (threshold {t['long_function_lines']}).",
                    impact="Long functions hide multiple responsibilities, are hard to test and review, and attract "
                           "bugs during change.",
                    remediation="Extract cohesive steps into well-named helper functions and keep each function to "
                                "one level of abstraction.", confidence="high", source="static-metrics",
                    verification=V_HEURISTIC, family="long-function", tags=["metric"]))
            if f.complexity > t["max_complexity"]:
                very = f.complexity > t["very_high_complexity"]
                out.append(build_finding(
                    sf, rule_id="SLOP-COMPLEXITY", title=f"High cyclomatic complexity in `{f.name}` ({f.complexity})",
                    category=CAT_SLOP, subcategory=SUB_COMPLEXITY, severity="medium" if very else "low",
                    line=f.start, end_line=f.end,
                    explanation=f"Estimated cyclomatic complexity is {f.complexity} (threshold {t['max_complexity']}).",
                    impact="Many independent paths make the function expensive to test exhaustively and easy to break.",
                    remediation="Split branches into helpers, use early returns/guard clauses or lookup tables.",
                    confidence="high" if sf.lang_name == "Python" else "medium", source="static-metrics",
                    verification=V_HEURISTIC, family="complexity", tags=["metric"]))
            nest_limit = t["max_nesting"] + (1 if sf.lang_name != "Python" else 0)
            if f.nesting > nest_limit:
                out.append(build_finding(
                    sf, rule_id="SLOP-NESTING", title=f"Excessive nesting in `{f.name}` (depth {f.nesting})",
                    category=CAT_SLOP, subcategory=SUB_COMPLEXITY, severity="low", line=f.start, end_line=f.end,
                    explanation=f"Control-flow nesting reaches depth {f.nesting} (threshold {nest_limit}).",
                    impact="Deeply nested code is hard to read and reason about.",
                    remediation="Flatten with guard clauses, extract inner blocks, or invert conditions.",
                    confidence="medium", source="static-metrics", verification=V_HEURISTIC, family="nesting",
                    tags=["metric"]))
            if f.params > t["max_params"]:
                out.append(build_finding(
                    sf, rule_id="SLOP-PARAMS", title=f"Too many parameters in `{f.name}` ({f.params})",
                    category=CAT_SLOP, subcategory=SUB_COMPLEXITY, severity="low", line=f.start,
                    explanation=f"The function takes {f.params} parameters (threshold {t['max_params']}).",
                    impact="Long parameter lists are error-prone at call sites and signal missing abstractions.",
                    remediation="Group related parameters into an object/dataclass.", confidence="high",
                    source="static-metrics", verification=V_HEURISTIC, family="params", tags=["metric"]))
            if f.name.startswith("<") or " " in f.name:
                continue_naming = False
            else:
                continue_naming = True
            if continue_naming and ((len(f.name) <= 1 and f.name not in ALLOWED_SHORT) or BAD_NAMES.match(f.name)):
                out.append(build_finding(
                    sf, rule_id="SLOP-NAMING", title=f"Non-descriptive function name `{f.name}`",
                    category=CAT_SLOP, subcategory=SUB_NAMING, severity="low", line=f.start,
                    explanation="The name does not describe behaviour.", impact="Reduces readability and searchability.",
                    remediation="Rename to a verb phrase describing what the function does.", confidence="medium",
                    source="static-metrics", verification=V_HEURISTIC, family="naming"))
            # pass-through wrapper (unnecessary abstraction)
            wr = self._wrapper(f, sf)
            if wr:
                out.append(build_finding(
                    sf, rule_id="SLOP-WRAPPER", title=f"`{f.name}` only forwards to `{wr}`",
                    category=CAT_SLOP, subcategory=SUB_ABS, severity="low", line=f.start, end_line=f.end,
                    explanation=f"The body just calls `{wr}` with the same arguments and adds no behaviour.",
                    impact="Extra indirection without value makes call chains harder to follow.",
                    remediation="Call the target directly or give the wrapper real responsibility (validation, "
                                "error translation).", confidence="medium", source="static-metrics",
                    verification=V_HEURISTIC, family="wrapper"))
        if sf.lang_name == "Python" and tree is not None:
            out += self._python_extras(sf, tree, funcs)
        else:
            out += self._clike_extras(sf, funcs)
        return out

    # ----------------------------------------------------------- helpers
    def _wrapper(self, f: FuncInfo, sf: SourceFile) -> str | None:
        if f.params == 0 or f.length > 4 or (f.decorators and sf.lang_name == "Python"):
            return None
        if f.node is not None:
            body = [s for s in f.node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
            if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Call):
                call = body[0].value
                params = [a.arg for a in f.node.args.args if a.arg not in ("self", "cls")]
                passed = [a.id for a in call.args if isinstance(a, ast.Name)]
                if (params and passed == params and not call.keywords
                        and isinstance(call.func, (ast.Name, ast.Attribute)) and len(passed) == len(call.args)):
                    return ast.unparse(call.func)
        return None

    def _python_extras(self, sf: SourceFile, tree: ast.AST, funcs: list[FuncInfo]) -> list[Finding]:
        out: list[Finding] = []
        used_names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attr_roots = {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
        string_blob = " ".join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                               and len(n.value) < 120)
        exported: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets):
                exported |= {e.value for e in ast.walk(n.value) if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        # unused imports
        if not sf.rel.endswith("__init__.py"):
            guarded = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Try):
                    for s in n.body:
                        guarded.update(id(x) for x in ast.walk(s))
                if isinstance(n, ast.If) and "TYPE_CHECKING" in ast.dump(n.test):
                    for s in n.body:
                        guarded.update(id(x) for x in ast.walk(s))
            for n in ast.walk(tree):
                if not isinstance(n, (ast.Import, ast.ImportFrom)) or id(n) in guarded:
                    continue
                if isinstance(n, ast.ImportFrom) and (n.module == "__future__"):
                    continue
                for alias in n.names:
                    if alias.name == "*":
                        continue
                    bound = (alias.asname or alias.name).split(".")[0]
                    if alias.asname and alias.asname == alias.name:
                        continue
                    if bound in used_names or bound in attr_roots or bound in exported or \
                            re.search(rf"\b{re.escape(bound)}\b", string_blob):
                        continue
                    out.append(build_finding(
                        sf, rule_id="SLOP-UNUSED-IMPORT", title=f"Unused import `{bound}`", category=CAT_SLOP,
                        subcategory=SUB_UNUSED, severity="low", line=n.lineno,
                        explanation=f"`{bound}` is imported but never referenced in this module.",
                        impact="Dead imports slow start-up, clutter the file and may hide missing dependencies.",
                        remediation="Remove the import (or re-export it explicitly via `__all__`).",
                        confidence="high", source="python-ast", verification=V_HEURISTIC, family="unused-import"))
        # unused local variables + dead code after terminal statements
        for f in funcs:
            fn = f.node
            if fn is None:
                continue
            dyn = any(isinstance(n, ast.Name) and n.id in ("locals", "vars", "eval", "exec") for n in ast.walk(fn))
            declared = {n for node in ast.walk(fn) if isinstance(node, (ast.Global, ast.Nonlocal)) for n in node.names}
            if not dyn:
                assigned: dict[str, int] = {}
                loaded = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Load, ast.Del))}
                for node in ast.walk(fn):
                    tgts = []
                    if isinstance(node, ast.Assign):
                        tgts = [t for t in node.targets if isinstance(t, ast.Name)]
                    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                        tgts = [node.target]
                    for t in tgts:
                        assigned.setdefault(t.id, t.lineno)
                for name, ln in assigned.items():
                    if name not in loaded and not name.startswith("_") and name not in declared:
                        out.append(build_finding(
                            sf, rule_id="SLOP-UNUSED-VAR", title=f"Unused local variable `{name}` in `{f.name}`",
                            category=CAT_SLOP, subcategory=SUB_UNUSED, severity="low", line=ln,
                            explanation=f"`{name}` is assigned but never read inside `{f.name}`.",
                            impact="Indicates leftover or incomplete logic and adds noise.",
                            remediation="Remove the assignment or use the value.", confidence="high",
                            source="python-ast", verification=V_HEURISTIC, family="unused-variable"))
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            for block in (body, getattr(node, "orelse", None), getattr(node, "finalbody", None)):
                if not isinstance(block, list):
                    continue
                for i, st in enumerate(block[:-1]):
                    if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        nxt = block[i + 1]
                        if isinstance(nxt, ast.Expr) and isinstance(nxt.value, ast.Constant):
                            continue
                        out.append(build_finding(
                            sf, rule_id="SLOP-DEAD-CODE", title="Unreachable code after terminal statement",
                            category=CAT_SLOP, subcategory=SUB_DEAD, severity="medium", line=nxt.lineno,
                            explanation=f"Code follows a `{type(st).__name__.lower()}` in the same block and can never run.",
                            impact="Dead code misleads readers and often marks a failed refactor.",
                            remediation="Delete the unreachable statements or fix the control flow.",
                            confidence="high", source="python-ast", verification=V_STATIC, family="dead-code"))
                        break
            if isinstance(node, (ast.If, ast.While)) and isinstance(node.test, ast.Constant) and \
                    node.test.value in (False, 0) and not isinstance(node.test.value, str):
                out.append(build_finding(
                    sf, rule_id="SLOP-DEAD-CODE", title="Block guarded by constant-false condition",
                    category=CAT_SLOP, subcategory=SUB_DEAD, severity="low", line=node.lineno,
                    explanation="The condition is always false, so the body never executes.",
                    impact="Dead code adds noise.", remediation="Remove the block or the condition.",
                    confidence="high", source="python-ast", verification=V_STATIC, family="dead-code"))
            if isinstance(node, ast.ExceptHandler) and (node.type is None or (
                    isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))):
                if not all(isinstance(s, (ast.Pass, ast.Expr)) for s in node.body) or len(node.body) > 1:
                    reraises = any(isinstance(s, ast.Raise) for s in ast.walk(node))
                    if not reraises:
                        out.append(build_finding(
                            sf, rule_id="SLOP-GENERIC-EXCEPT",
                            title="Overly generic exception handler", category=CAT_SLOP, subcategory=SUB_EXC,
                            severity="low", line=node.lineno,
                            explanation="Catching `Exception`/bare `except` handles every error identically.",
                            impact="Unrelated bugs are masked and failures become hard to diagnose.",
                            remediation="Catch the specific exceptions you can handle and let others propagate.",
                            confidence="medium", source="python-ast", verification=V_HEURISTIC,
                            family="generic-exception"))
        # unnecessary abstraction: class with only __init__ + one method
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and not node.bases and not node.decorator_list:
                methods = [m for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
                others = [m for m in node.body if not isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Expr, ast.Pass))]
                names = [m.name for m in methods]
                if len(methods) == 2 and "__init__" in names and not others:
                    other = next(m for m in methods if m.name != "__init__")
                    if not other.name.startswith("__") and not other.decorator_list:
                        out.append(build_finding(
                            sf, rule_id="SLOP-SINGLE-METHOD-CLASS", title=f"Class `{node.name}` wraps a single function",
                            category=CAT_SLOP, subcategory=SUB_ABS, severity="low", line=node.lineno,
                            explanation="The class holds state only to expose one method.",
                            impact="A class where a function (or functools.partial) would do adds ceremony.",
                            remediation="Consider a plain function unless more behaviour is planned.",
                            confidence="low", source="python-ast", verification=V_HEURISTIC, family="abstraction"))
        # poor variable naming (aggregated)
        bad: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and BAD_NAMES.match(node.id):
                bad.append((node.id, node.lineno))
        if bad:
            seen = {}
            for n, ln in bad:
                seen.setdefault(n, ln)
            n0, l0 = next(iter(seen.items()))
            out.append(build_finding(
                sf, rule_id="SLOP-NAMING", title=f"Non-descriptive variable names ({', '.join(list(seen)[:4])})",
                category=CAT_SLOP, subcategory=SUB_NAMING, severity="low", line=l0,
                explanation="Placeholder-style variable names (temp1, data2, foo, ...) do not describe content.",
                impact="Reduces readability; often left from quick drafts.",
                remediation="Rename variables after the data they hold.", confidence="medium",
                source="python-ast", verification=V_HEURISTIC, family="naming",
                occurrences=[{"line": ln, "snippet": sf.lines[ln - 1].strip()[:120]} for ln in seen.values()][:10]))
        return out

    def _clike_extras(self, sf: SourceFile, funcs: list[FuncInfo]) -> list[Finding]:
        out: list[Finding] = []
        text = sf.nocomment
        blank = sf.blanked
        if sf.lang_name in ("JavaScript", "TypeScript") and not sf.is_test:
            lines = blank.split("\n")
            # unused imports
            for m in re.finditer(r"^\s*import\s+(?:type\s+)?([^'\";]+?)\s+from\s+['\"][^'\"]+['\"]", text, re.M):
                clause = m.group(1)
                names = re.findall(r"[A-Za-z_$][\w$]*", re.sub(r"\bas\s+(\w+)", r"\1", clause.replace("*", "")))
                names = [n for n in names if n not in ("type", "as")]
                ln = text.count("\n", 0, m.start()) + 1
                for n in names:
                    if n == "React" or n == "default":
                        continue
                    if len(re.findall(rf"(?<![\w$.]){re.escape(n)}(?![\w$])", blank)) <= 1:
                        out.append(build_finding(
                            sf, rule_id="SLOP-UNUSED-IMPORT", title=f"Unused import `{n}`", category=CAT_SLOP,
                            subcategory=SUB_UNUSED, severity="low", line=ln,
                            explanation=f"`{n}` is imported but not referenced afterwards.",
                            impact="Dead imports bloat bundles and clutter the file.", remediation="Remove the import.",
                            confidence="medium", source="static-metrics", verification=V_HEURISTIC,
                            family="unused-import"))
        if sf.lang_name == "Java":
            for m in re.finditer(r"^\s*import\s+(?!static)([\w.]+)\.(\w+)\s*;", text, re.M):
                simple = m.group(2)
                if len(re.findall(rf"\b{re.escape(simple)}\b", blank)) <= 1:
                    out.append(build_finding(
                        sf, rule_id="SLOP-UNUSED-IMPORT", title=f"Unused import `{simple}`", category=CAT_SLOP,
                        subcategory=SUB_UNUSED, severity="low", line=text.count("\n", 0, m.start()) + 1,
                        explanation=f"`{m.group(1)}.{simple}` is imported but never used.",
                        impact="Dead imports clutter the file.", remediation="Remove the import.", confidence="high",
                        source="static-metrics", verification=V_HEURISTIC, family="unused-import"))
            # getter/setter boilerplate
            trivial = re.findall(r"\b(?:get|set|is)[A-Z]\w*\s*\([^)]*\)\s*\{\s*(?:return\s+(?:this\.)?\w+\s*;|"
                                 r"(?:this\.)?\w+\s*=\s*\w+\s*;)\s*\}", blank)
            if len(trivial) >= 10 and "@Data" not in text:
                out.append(build_finding(
                    sf, rule_id="SLOP-BOILERPLATE", title=f"Getter/setter boilerplate ({len(trivial)} trivial accessors)",
                    category=CAT_SLOP, subcategory=SUB_BOILER, severity="low", line=1,
                    explanation=f"{len(trivial)} accessor methods only read/write a field.",
                    impact="Large amounts of mechanical code obscure real logic.",
                    remediation="Use records / Lombok (@Data) or reduce mutable state.", confidence="medium",
                    source="static-metrics", verification=V_HEURISTIC, family="boilerplate", evidence=sf.lines[0] if sf.lines else ""))
        # generic exception handling (catch Exception / Throwable with non-empty body)
        for m in re.finditer(r"catch\s*\(\s*(?:final\s+)?(Exception|Throwable|RuntimeException)\s+\w+\s*\)\s*\{([^{}]*)\}", blank):
            body = m.group(2).strip()
            if body and "throw" not in body:
                out.append(build_finding(
                    sf, rule_id="SLOP-GENERIC-EXCEPT", title=f"Overly generic `catch ({m.group(1)})`",
                    category=CAT_SLOP, subcategory=SUB_EXC, severity="low",
                    line=blank.count("\n", 0, m.start()) + 1,
                    explanation="Catching the base exception type handles unrelated failures identically.",
                    impact="Bugs and infrastructure failures get masked.", remediation="Catch specific exception types.",
                    confidence="medium", source="static-metrics", verification=V_HEURISTIC, family="generic-exception"))
        # dead code: statement after return/throw in the same block
        for m in re.finditer(r"\b(?:return\b[^;{}]*|throw\b[^;{}]*|break|continue)\s*;[ \t]*\n\s*(?!\}|case\b|default\b|//|/\*)"
                             r"([A-Za-z_$][^\n]*;)", blank):
            out.append(build_finding(
                sf, rule_id="SLOP-DEAD-CODE", title="Unreachable code after terminal statement", category=CAT_SLOP,
                subcategory=SUB_DEAD, severity="medium", line=blank.count("\n", 0, m.start(1)) + 1,
                explanation="A statement follows return/throw/break/continue in the same block.",
                impact="Dead code misleads readers.", remediation="Remove it or fix control flow.",
                confidence="medium", source="static-metrics", verification=V_POTENTIAL, family="dead-code"))
        # poor variable names
        names = {}
        for m in re.finditer(r"\b(?:let|const|var|int|long|String|double|boolean|List<\w+>|Map<[^>]+>)\s+([A-Za-z_$][\w$]*)\s*[=;]", blank):
            if BAD_NAMES.match(m.group(1)):
                names.setdefault(m.group(1), blank.count("\n", 0, m.start()) + 1)
        if names:
            n0, l0 = next(iter(names.items()))
            out.append(build_finding(
                sf, rule_id="SLOP-NAMING", title=f"Non-descriptive variable names ({', '.join(list(names)[:4])})",
                category=CAT_SLOP, subcategory=SUB_NAMING, severity="low", line=l0,
                explanation="Placeholder-style names (temp1, data2, foo, ...) do not describe content.",
                impact="Reduces readability.", remediation="Rename variables after the data they hold.",
                confidence="medium", source="static-metrics", verification=V_HEURISTIC, family="naming",
                occurrences=[{"line": ln, "snippet": sf.lines[ln - 1].strip()[:120]} for ln in names.values()][:10]))
        return out


# =====================================================================================
@register
class CommentSlopAnalyzer(Analyzer):
    """Redundant comments and commented-out code."""
    name = "slop-comments"
    stage = "slop"
    languages = ("Python", "Java", "JavaScript", "TypeScript")

    STOP = {"the", "a", "an", "to", "of", "and", "for", "in", "is", "this", "that", "it", "we", "if", "then", "set",
            "get", "new", "create", "creates", "call", "calls", "return", "returns", "function", "method", "variable",
            "initialize", "init", "check", "checks", "loop", "through", "over", "each", "add", "increment", "decrement",
            "define", "assign", "print", "import", "class", "update", "value", "with", "from", "by", "on", "all", "now"}
    CODEISH = re.compile(r"(?:;\s*$|^\s*(?:if|for|while|return|import|from|def|class|try|except|else|elif|var|let|const|"
                         r"function|print|console\.)\b.*[(:{=]|\)\s*\{?\s*$|^\s*[\w.\[\]]+\s*=\s*[^=]|\w+\([^)]*\)\s*;?$)")

    @staticmethod
    def _tokens(s: str) -> list[str]:
        s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
        return [t.lower() for t in re.findall(r"[A-Za-z]+", s)]

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        out: list[Finding] = []
        lines = sf.lines
        comments = [(ln, c) for ln, c in sf.comments if not c.startswith("/*")]
        by_line = dict(comments)
        # redundant comments: comment restating the immediately following code line
        for ln, c in comments:
            body = re.sub(r"^(?:#|//)+\s*", "", c).strip()
            if len(body) < 6 or re.search(r"(?i)todo|fixme|hack|xxx|noqa|type:|pylint|eslint|istanbul|pragma|nosec|"
                                          r"https?://|why|because|workaround|note|warning|must|ensure|otherwise", body):
                continue
            ctoks = [t for t in self._tokens(body) if t not in self.STOP]
            if not (1 <= len(ctoks) <= 4) or len(self._tokens(body)) > 6:
                continue
            if ln >= len(lines) or (ln + 1) in by_line:
                continue
            nxt = lines[ln].strip()
            if not nxt or len(nxt) > 90:
                continue
            ntoks = set(self._tokens(nxt))
            if all(t in ntoks or t.rstrip("s") in ntoks or t + "s" in ntoks for t in ctoks):
                out.append(build_finding(
                    sf, rule_id="SLOP-REDUNDANT-COMMENT", title="Comment restates the code",
                    category=CAT_SLOP, subcategory=SUB_COMMENTS, severity="low", line=ln, end_line=ln + 1,
                    explanation="The comment only repeats what the next line already says.",
                    impact="Noise comments drift out of date and add reading overhead.",
                    remediation="Delete it, or explain *why* the code does this instead of *what* it does.",
                    confidence="low", source="static-metrics", verification=V_HEURISTIC, family="redundant-comment",
                    evidence=f"{c.strip()}  →  {nxt}"))
        # commented-out code blocks (>= 3 consecutive code-looking comment lines)
        run: list[tuple[int, str]] = []
        for ln, c in comments + [(10**9, "")]:
            body = re.sub(r"^(?:#|//)+\s?", "", c)
            if run and ln != run[-1][0] + 1:
                if len(run) >= 3:
                    out.append(build_finding(
                        sf, rule_id="SLOP-COMMENTED-CODE", title=f"Commented-out code block ({len(run)} lines)",
                        category=CAT_SLOP, subcategory=SUB_DEAD, severity="low", line=run[0][0], end_line=run[-1][0],
                        explanation="Several consecutive comment lines look like disabled source code.",
                        impact="Dead code in comments rots and confuses readers; version control already keeps history.",
                        remediation="Delete the block (retrieve it from git if needed).", confidence="medium",
                        source="static-metrics", verification=V_HEURISTIC, family="commented-code",
                        evidence="\n".join(lines[run[0][0] - 1: run[0][0] + 2])[:300]))
                run = []
            if ln < 10**9 and self.CODEISH.search(body) and len(body.strip()) > 3:
                run.append((ln, body))
            elif run and ln < 10**9:
                if len(run) >= 3:
                    pass
        return out


# =====================================================================================
def _norm_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


TRIVIAL_LINES = {"", "}", "{", "});", "};", ")", "]", "end", "else:", "else", "try:", "try {", "} else {", "break;",
                 "break", "continue", "pass", "return", "return;", "});", "},", "]);", "} catch (e) {", "finally:"}


@register
class DuplicationAnalyzer(Analyzer):
    """Duplicate functions and repeated code blocks across the whole project."""
    name = "slop-duplication"
    stage = "slop"

    def analyze_project(self, ctx: ProjectContext):
        t = ctx.threshold
        out: list[Finding] = []
        funcs_by_hash: dict[str, list[tuple[SourceFile, FuncInfo]]] = defaultdict(list)
        dup_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
        files = [f for f in ctx.files if f.language and f.lang_name in ("Python", "Java", "JavaScript", "TypeScript")
                 and not f.is_test]
        for sf in files:
            for f in get_functions(sf):
                if f.length < t["min_duplicate_function_lines"] or f.stmt_count < 3 or f.name in ("__init__", "constructor"):
                    continue
                key = hashlib.sha1(f.body_text.encode("utf-8", "replace")).hexdigest()
                funcs_by_hash[key].append((sf, f))
        for group in funcs_by_hash.values():
            if len(group) < 2:
                continue
            first_sf, first = group[0]
            for sf, f in group:
                dup_ranges[sf.rel].append((f.start, f.end))
            others = [{"file": sf.rel, "line": f.start, "snippet": f"{f.name} ({f.length} lines)"} for sf, f in group[1:]]
            out.append(build_finding(
                first_sf, rule_id="SLOP-DUP-FUNCTION",
                title=f"Duplicate function body: `{first.name}` ×{len(group)}", category=CAT_SLOP,
                subcategory=SUB_DUP, severity="medium" if len(group) > 2 or first.length > 20 else "low",
                line=first.start, end_line=first.end,
                explanation=f"{len(group)} functions have identical bodies ({first.length} lines each).",
                impact="Fixes must be applied in several places, and copies drift apart over time.",
                remediation="Extract the shared logic into one function/module and call it from each place.",
                confidence="high", source="static-metrics", verification=V_HEURISTIC, family="duplicate-function",
                occurrences=[{"file": first_sf.rel, "line": first.start, "snippet": f"{first.name} (original)"}] + others))
        out += self._repeated_blocks(ctx, files, dup_ranges)
        return out

    def _repeated_blocks(self, ctx, files, dup_ranges):
        W = int(ctx.threshold["duplicate_window_lines"])
        seqs: dict[str, list[tuple[int, str]]] = {}
        total = 0
        for sf in files:
            norm = []
            for i, ln in enumerate(sf.nocomment.split("\n"), 1):
                n = _norm_line(ln)
                if n in TRIVIAL_LINES or re.match(r"^(import|from|require|using|package|#include|export \{)\b", n) \
                        or n.startswith(("@", "//", "#")) or len(n) < 4:
                    continue
                norm.append((i, n))
            if len(norm) >= W:
                seqs[sf.rel] = norm
                total += len(norm)
            if total > 250_000:
                break
        index: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for rel, norm in seqs.items():
            for k in range(len(norm) - W + 1):
                h = hashlib.sha1("\n".join(n for _, n in norm[k:k + W]).encode()).hexdigest()
                index[h].append((rel, k))
        covered: dict[str, set[int]] = defaultdict(set)
        by_rel = {f.rel: f for f in files}
        out: list[Finding] = []
        processed: set[tuple[str, int]] = set()
        for rel, norm in seqs.items():
            k = 0
            while k <= len(norm) - W:
                h = hashlib.sha1("\n".join(n for _, n in norm[k:k + W]).encode()).hexdigest()
                occ = index[h]
                if len(occ) < 2 or (rel, k) in processed or k in covered[rel]:
                    k += 1
                    continue
                # extend while every occurrence continues to match
                length = W
                while True:
                    nxt = []
                    ok = True
                    for orel, ok_k in occ:
                        s2 = seqs[orel]
                        a = ok_k + length
                        if a >= len(s2):
                            ok = False
                            break
                        nxt.append((orel, ok_k, s2[a][1]))
                    if not ok or len({x[2] for x in nxt}) != 1:
                        break
                    length += 1
                chars = sum(len(n) for _, n in norm[k:k + length])
                for orel, ok_k in occ:
                    for j in range(ok_k, ok_k + length):
                        covered[orel].add(j)
                    processed.add((orel, ok_k))
                    for j in range(ok_k, ok_k + length - W + 1):
                        processed.add((orel, j))
                k += 1
                if chars < 160:
                    continue
                locs = []
                for orel, ok_k in occ:
                    s2 = seqs[orel]
                    locs.append((orel, s2[ok_k][0], s2[ok_k + length - 1][0]))
                # skip blocks entirely inside already-reported duplicate functions
                if all(any(a <= l0 and l1 <= b for a, b in dup_ranges.get(orel, [])) for orel, l0, l1 in locs):
                    continue
                locs = sorted(set(locs))
                f0 = locs[0]
                sf = by_rel[f0[0]]
                out.append(build_finding(
                    sf, rule_id="SLOP-DUP-BLOCK", title=f"Repeated code block ({length} lines, {len(locs)} places)",
                    category=CAT_SLOP, subcategory=SUB_DUP, severity="medium" if length >= 15 or len(locs) > 3 else "low",
                    line=f0[1], end_line=f0[2],
                    explanation=f"The same {length} meaningful lines appear in {len(locs)} places.",
                    impact="Copy-pasted logic multiplies bugs and maintenance effort.",
                    remediation="Extract the repeated logic into a shared helper.", confidence="high",
                    source="static-metrics", verification=V_HEURISTIC, family="repeated-code",
                    occurrences=[{"file": r, "line": a, "snippet": f"lines {a}-{b}"} for r, a, b in locs]))
        return out


# =====================================================================================
PY_IMPORT_MAP = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
                 "opencv-python": "cv2", "opencv-python-headless": "cv2", "python-dotenv": "dotenv",
                 "flask-cors": "flask_cors", "python-dateutil": "dateutil", "pymysql": "pymysql",
                 "psycopg2-binary": "psycopg2", "google-genai": "google", "protobuf": "google",
                 "attrs": "attr", "pyjwt": "jwt", "msgpack-python": "msgpack", "python-jose": "jose",
                 "mysqlclient": "MySQLdb", "pycryptodome": "Crypto", "flask-sqlalchemy": "flask_sqlalchemy"}
PY_TOOLING = {"pytest", "pytest-cov", "black", "flake8", "pylint", "mypy", "isort", "ruff", "bandit", "semgrep",
              "tox", "coverage", "gunicorn", "uvicorn", "wheel", "setuptools", "pip", "build", "twine", "pre-commit",
              "ipython", "jupyter", "sphinx", "hypothesis", "nose", "pyflakes", "autopep8", "waitress", "honcho"}
JS_TOOLING = re.compile(r"^(?:@types/|eslint|prettier|typescript$|vite|webpack|jest|babel|@babel|postcss|tailwind|"
                        r"autoprefixer|nodemon|ts-node|ts-jest|mocha|chai|cypress|playwright|vitest|rollup|esbuild|"
                        r"husky|lint-staged|concurrently|cross-env|dotenv-cli|@vitejs|@testing-library|supertest|"
                        r"sass|less|stylelint|npm-run-all|rimraf|nyc|c8|sinon|karma|gulp|grunt|parcel|swc|@swc)")


@register
class DependencyAnalyzer(Analyzer):
    """Declared-but-never-imported dependencies (potential unnecessary dependencies)."""
    name = "slop-dependencies"
    stage = "slop"

    def analyze_project(self, ctx: ProjectContext):
        out: list[Finding] = []
        mf = {f.rel: f for f in ctx.files}
        py_imports: set[str] = set()
        js_imports: str = ""
        for f in ctx.files:
            if f.lang_name == "Python":
                for m in re.finditer(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", f.nocomment, re.M):
                    mod = m.group(1) or m.group(2)
                    for part in mod.split(","):
                        py_imports.add(part.strip().split(" as ")[0].split(".")[0].lower())
            elif f.lang_name in ("JavaScript", "TypeScript", "HTML"):
                js_imports += "\n" + f.text
        for rel, text in ctx.manifests.items():
            sf = mf.get(rel)
            if sf is None:
                continue
            base = os.path.basename(rel)
            if base == "requirements.txt" and py_imports:
                for i, line in enumerate(text.splitlines(), 1):
                    line = line.split("#")[0].strip()
                    if not line or line.startswith(("-", "http")):
                        continue
                    name = re.split(r"[=<>!~\[; ]", line)[0].strip().lower()
                    if not name or name in PY_TOOLING:
                        continue
                    mod = PY_IMPORT_MAP.get(name, name).lower().replace("-", "_")
                    if mod not in py_imports and name.replace("-", "_") not in py_imports:
                        out.append(self._f(sf, name, i, line))
            elif base == "package.json":
                try:
                    pkg = json.loads(text)
                except ValueError:
                    continue
                scripts = " ".join(str(v) for v in (pkg.get("scripts") or {}).values())
                for dep in (pkg.get("dependencies") or {}):
                    if JS_TOOLING.match(dep) or dep in scripts:
                        continue
                    if not re.search(rf"""['"`]{re.escape(dep)}(?:/[^'"`]*)?['"`]""", js_imports):
                        ln = next((i for i, l in enumerate(text.splitlines(), 1) if f'"{dep}"' in l), 1)
                        out.append(self._f(sf, dep, ln, f'"{dep}": "{pkg["dependencies"][dep]}"'))
        return out

    def _f(self, sf, name, line, evidence):
        return build_finding(
            sf, rule_id="SLOP-UNUSED-DEPENDENCY", title=f"Dependency `{name}` is never imported",
            category=CAT_SLOP, subcategory=SUB_DEPS, severity="low", line=line, evidence=evidence,
            explanation=f"`{name}` is declared in the manifest but no import/require of it was found in the analysed sources.",
            impact="Unused dependencies increase install size, attack surface and supply-chain risk.",
            remediation="Remove it if it is truly unused (check dynamic imports, plugins and build tooling first).",
            confidence="low", source="static-metrics", verification=V_POTENTIAL, family="unused-dependency")
