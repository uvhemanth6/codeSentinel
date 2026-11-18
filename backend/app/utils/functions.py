"""Function extraction + metrics for Python (AST) and C-like languages (brace matching on a blanked view)."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..models.source import SourceFile

CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "return", "else", "function", "new", "throw", "do", "try",
                 "synchronized", "with", "await", "typeof", "super", "this", "elif"}


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    params: int
    complexity: int
    nesting: int
    body_lines: int
    body_text: str = ""          # normalised body (for duplicate detection)
    node: ast.AST | None = None
    decorators: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None
    stmt_count: int = 0

    @property
    def length(self) -> int:
        return self.end - self.start + 1


# ---------------------------------------------------------------- Python
_NEST = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)


def _py_nesting(node: ast.AST, depth: int = 0) -> int:
    best = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        d = depth + 1 if isinstance(child, _NEST) else depth
        best = max(best, _py_nesting(child, d))
    return best


def _py_complexity(fn: ast.AST) -> int:
    c = 1
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
        elif hasattr(ast, "match_case") and isinstance(n, ast.match_case):
            c += 1
        stack.extend(ast.iter_child_nodes(n))
    return c


class _Normalizer(ast.NodeTransformer):
    def visit_Constant(self, node):  # keep structure, drop docstring identity
        return node


def python_functions(tree: ast.AST) -> list[FuncInfo]:
    out: list[FuncInfo] = []

    def visit(node: ast.AST, cls: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = child.body
                if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    body = body[1:]
                end = getattr(child, "end_lineno", child.lineno)
                a = child.args
                nparams = len(a.args) + len(a.kwonlyargs) + len(getattr(a, "posonlyargs", [])) \
                    - (1 if a.args and a.args[0].arg in ("self", "cls") else 0)
                dump = "|".join(ast.dump(s, annotate_fields=False, include_attributes=False) for s in body)
                decos = []
                for d in child.decorator_list:
                    dd = d.func if isinstance(d, ast.Call) else d
                    decos.append(ast.unparse(dd) if hasattr(ast, "unparse") else "")
                out.append(FuncInfo(child.name, child.lineno, end, nparams, _py_complexity(child), _py_nesting(child),
                                    end - child.lineno + 1, dump, child, decos, cls is not None, cls, len(body)))
                visit(child, None if cls is None else cls)
            else:
                visit(child, cls)

    visit(tree, None)
    return out


# ---------------------------------------------------------------- C-like
_JS_FUNC = re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(([^()]*)\)\s*(?::\s*[^{;=]+?)?\s*\{")
_JS_ARROW = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?"
                       r"(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*(?::\s*[^=>{\n]+)?=>\s*\{")
_JS_ARROW_ANON = re.compile(r"(?:async\s*)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*(?::\s*[^=>{\n]+)?=>\s*\{")
_ROUTE_HEAD = re.compile(r"(\w+)\.(get|post|put|delete|patch|use|all|on)\(\s*[\'\"`]([^\'\"`]*)[\'\"`]")
_METHOD = re.compile(r"^[ \t]*(?:(?:public|private|protected|static|final|abstract|synchronized|async|override|"
                     r"readonly|get|set|default|native|export)\s+)*(?:<[^>]+>\s+)?(?:[\w<>\[\],.?$]+(?:\s*<[^>]*>)?\s+)?"
                     r"([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?::\s*[^{;=\n]+?)?\s*(?:throws\s+[\w.,\s]+)?\{", re.M)


def _match_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _count_params(raw: str | None) -> int:
    raw = (raw or "").strip()
    return 0 if not raw else len([p for p in raw.split(",") if p.strip()])


def _cl_metrics(body: str) -> tuple[int, int]:
    complexity = 1 + len(re.findall(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?(?![.?])", body))
    depth = best = 0
    for c in body[1:]:
        if c == "{":
            depth += 1
            best = max(best, depth)
        elif c == "}":
            depth -= 1
    return complexity, best


def clike_functions(sf: SourceFile) -> list[FuncInfo]:
    text = sf.blanked
    out: list[FuncInfo] = []
    seen: set[int] = set()
    cands: list[tuple[str, int, str, int]] = []  # name, brace_idx, params, match_start
    for m in _JS_FUNC.finditer(text):
        cands.append((m.group(1) or "<anonymous>", m.end() - 1, m.group(2), m.start()))
    for m in _JS_ARROW.finditer(text):
        cands.append((m.group(1), m.end() - 1, m.group(2) or m.group(3) or "", m.start()))
    for m in _METHOD.finditer(text):
        name = m.group(1)
        if name in CONTROL_WORDS:
            continue
        cands.append((name, m.end() - 1, m.group(2), m.start()))
    if sf.lang_name in ("JavaScript", "TypeScript"):
        for m in _JS_ARROW_ANON.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            head = _ROUTE_HEAD.search(sf.nocomment[line_start:m.start()])
            nm = f"{head.group(2).upper()} {head.group(3)}" if head else "<arrow>"
            cands.append((nm, m.end() - 1, m.group(1) or m.group(2) or "", m.start()))
    cands.sort(key=lambda c: c[1])
    for name, bi, params, ms in cands:
        if bi in seen:
            continue
        seen.add(bi)
        end = _match_brace(text, bi)
        if end == -1:
            continue
        body = text[bi:end + 1]
        start_line = text.count("\n", 0, ms) + 1
        # the method regex may start on the preceding blank line
        while start_line <= len(sf.lines) and not sf.lines[start_line - 1].strip():
            start_line += 1
        end_line = text.count("\n", 0, end) + 1
        comp, nest = _cl_metrics(body)
        norm = re.sub(r"\s+", " ", body).strip()
        out.append(FuncInfo(name, start_line, end_line, _count_params(params), comp, nest, end_line - start_line + 1,
                            norm, None, [], False, None, body.count(";")))
    return out


def get_functions(sf: SourceFile, tree: ast.AST | None = None) -> list[FuncInfo]:
    if sf.lang_name == "Python":
        if tree is None:
            try:
                tree = ast.parse(sf.text)
            except (SyntaxError, ValueError):
                return []
        return python_functions(tree)
    if sf.lang_name in ("Java", "JavaScript", "TypeScript"):
        return clike_functions(sf)
    return []
