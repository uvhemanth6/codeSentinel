"""Python AST security checks (more precise than regex: they look at how a call is invoked)."""
from __future__ import annotations

import ast

from ..models.finding import CAT_SECURITY, V_POTENTIAL, V_STATIC
from ..models.source import ProjectContext, SourceFile
from .base import Analyzer, build_finding, register

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "text"}
SHELL_FUNCS = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}
SUBPROC = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}


def dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def is_dynamic(node: ast.AST) -> bool:
    """True when the expression builds a string from runtime data."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (is_const_str(node.left) and is_const_str(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


@register
class PythonAstSecurityAnalyzer(Analyzer):
    name = "python-ast-security"
    stage = "security"
    languages = ("Python",)

    def analyze_file(self, sf: SourceFile, ctx: ProjectContext):
        try:
            tree = ast.parse(sf.text)
        except (SyntaxError, ValueError):
            return []
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            args = node.args
            if attr in SQL_METHODS and args and is_dynamic(args[0]) and not sf.is_test:
                out.append(build_finding(
                    sf, rule_id="SEC-SQLI-PY", title="SQL executed with dynamically built query",
                    category=CAT_SECURITY, subcategory="Injection", severity="high", line=node.lineno,
                    explanation=f"`{attr}()` receives a query assembled with string formatting/concatenation.",
                    impact="Attacker-controlled values can change the query structure (SQL injection).",
                    remediation="Pass parameters separately: `cursor.execute('... WHERE id = %s', (value,))`.",
                    confidence="high", source="python-ast", verification=V_STATIC, family="sql-injection",
                    cwe="CWE-89"))
            if name in SHELL_FUNCS and args and not is_const_str(args[0]):
                out.append(build_finding(
                    sf, rule_id="SEC-CMDI-PY", title="Shell command built from non-constant input",
                    category=CAT_SECURITY, subcategory="Injection", severity="high", line=node.lineno,
                    explanation=f"`{name}` runs its argument through a shell and the argument is not a constant.",
                    impact="Shell metacharacters in the dynamic part allow arbitrary command execution.",
                    remediation="Use `subprocess.run([...], shell=False)` with an argument list and validate input.",
                    confidence="high" if is_dynamic(args[0]) else "medium", source="python-ast",
                    verification=V_STATIC if is_dynamic(args[0]) else V_POTENTIAL, family="command-injection",
                    cwe="CWE-78"))
            elif name in SUBPROC:
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                                 for k in node.keywords)
                if shell_true:
                    dyn = bool(args) and not is_const_str(args[0])
                    out.append(build_finding(
                        sf, rule_id="SEC-CMDI-PY", title="subprocess call with shell=True",
                        category=CAT_SECURITY, subcategory="Injection", severity="high" if dyn else "low",
                        line=node.lineno,
                        explanation="`shell=True` hands the command to the system shell"
                        + (" and the command is built at runtime." if dyn else "."),
                        impact="Dynamic input can inject extra commands; even constants widen the attack surface.",
                        remediation="Pass an argument list and omit `shell=True`.",
                        confidence="high" if dyn else "medium", source="python-ast",
                        verification=V_STATIC if dyn else V_POTENTIAL, family="command-injection", cwe="CWE-78"))
        return out
