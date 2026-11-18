from conftest import rules


def test_python_slop_metrics(scan_files):
    body = "\n".join(f"    x{i} = {i}" for i in range(70))
    r = scan_files({"m.py": f'''
import os, sys
def big(a):
{body}
    return a
def nested(a):
    if a:
        for i in a:
            if i:
                while i:
                    if i > 1:
                        i -= 1
    return a
def dead():
    return 1
    print("x")
def unused():
    tmp = 5
    return 1
'''})
    got = rules(r, "Code Slop")
    assert {"SLOP-LONG-FUNCTION", "SLOP-NESTING", "SLOP-DEAD-CODE", "SLOP-UNUSED-IMPORT", "SLOP-UNUSED-VAR"} <= set(got)


def test_duplicate_functions_and_blocks(scan_files):
    fn = '''
def calc_{n}(items):
    total = 0
    for item in items:
        if item.get("active"):
            total += item["price"] * item["qty"]
    if total > 100:
        total -= 10
    return total
'''
    r = scan_files({"a.py": fn.format(n=1) + fn.format(n=2).replace("calc_2", "calc_2")})
    assert "SLOP-DUP-FUNCTION" in rules(r)


def test_unused_import_exemptions(scan_files):
    r = scan_files({"pkg/__init__.py": "from .a import thing\n",
                    "x.py": "from __future__ import annotations\nimport typing\nfrom os import path as path\n"
                            "try:\n    import ujson\nexcept ImportError:\n    ujson = None\n"})
    assert "SLOP-UNUSED-IMPORT" not in [f["rule_id"] for f in r["findings"] if f["file"] == "pkg/__init__.py"]
    unused = [f["title"] for f in r["findings"] if f["rule_id"] == "SLOP-UNUSED-IMPORT"]
    assert not any("ujson" in t or "annotations" in t for t in unused)


def test_abstract_and_intentional_empty_not_flagged(scan_files):
    r = scan_files({"base.py": '''
        from abc import ABC, abstractmethod
        from typing import Protocol
        class Base(ABC):
            @abstractmethod
            def run(self): ...
            @abstractmethod
            def stop(self):
                raise NotImplementedError
        class P(Protocol):
            def go(self) -> None: ...
        class E(Exception):
            pass
        class Hook:
            def on_start(self):
                """Hook for subclasses to override."""
                pass
    '''})
    gaps = [f for f in r["findings"] if f["rule_id"] in ("GAP-EMPTY-FUNCTION", "GAP-NOT-IMPLEMENTED")]
    assert gaps == []


def test_gaps_detected(scan_files):
    r = scan_files({"g.py": '''
        import requests
        def process_payment(order, card):
            pass
        def todo_thing(x):
            raise NotImplementedError
        def validate_user(user):
            return True
        def f():
            try:
                x = 1
            except Exception:
                pass
            requests.get("https://x.org")
            breakpoint()
    '''})
    got = set(rules(r))
    assert {"GAP-EMPTY-FUNCTION", "GAP-NOT-IMPLEMENTED", "GAP-PLACEHOLDER-RETURN", "GAP-EMPTY-EXCEPT",
            "GAP-NO-TIMEOUT", "DEBUG-BREAKPOINT"} <= got


def test_narrow_benign_except_not_flagged(scan_files):
    r = scan_files({"h.py": "try:\n    import foo\nexcept ImportError:\n    pass\n"})
    assert "GAP-EMPTY-EXCEPT" not in rules(r)


def test_markers_only_in_comments(scan_files):
    r = scan_files({"t.py": '# TODO: fix auth check\nx = "TODO inside string"\n# HACK workaround\n# XXX: odd\n# FIXME later\n'})
    marks = [f for f in r["findings"] if f["rule_id"].startswith("LOOSE-")]
    assert sorted(f["rule_id"] for f in marks) == ["LOOSE-FIXME", "LOOSE-HACK", "LOOSE-TODO", "LOOSE-XXX"]
    assert [f for f in marks if f["rule_id"] == "LOOSE-TODO"][0]["severity"] == "medium"  # security keyword


def test_js_gaps(scan_files):
    r = scan_files({"a.js": '''
        function empty() {}
        function notDone() { throw new Error("Not implemented"); }
        try { risky(); } catch (e) {}
        promise.catch(() => {});
        console.log("debug");
        class A { constructor() {} }
    '''})
    got = rules(r)
    assert {"GAP-EMPTY-FUNCTION", "GAP-NOT-IMPLEMENTED", "GAP-EMPTY-CATCH", "DEBUG-CONSOLE"} <= set(got)
    assert got.count("GAP-EMPTY-FUNCTION") == 1  # constructors / callbacks are exempt


def test_java_override_and_interface_exempt(scan_files):
    r = scan_files({"A.java": '''
        interface I { void go(); }
        abstract class B { abstract void run(); }
        class C extends B {
          @Override
          void run() { }
          void todo() { }
        }
    '''})
    names = [f["title"] for f in r["findings"] if f["rule_id"] == "GAP-EMPTY-FUNCTION"]
    assert names == ["Empty function body: `todo`"]


def test_config_and_sql(scan_files):
    r = scan_files({"q.sql": "DELETE FROM users;\nUPDATE t SET a=1 WHERE id=2;\nCREATE TABLE x (a int);\n",
                    "package.json": '{"name":"x","dependencies":{"a":"*"}}',
                    "bad.json": "{oops",
                    "d.yml": "services:\n  a:\n    privileged: true\n    image: nginx:latest\n"})
    got = set(rules(r))
    assert {"SQL-NO-WHERE", "SQL-NO-PK", "CFG-UNPINNED-DEP", "CFG-JSON-INVALID", "CFG-YAML-PRIVILEGED",
            "CFG-YAML-LATEST"} <= got
    assert [f for f in r["findings"] if f["rule_id"] == "SQL-NO-WHERE"][0]["line"] == 1


def test_unused_dependency(scan_files):
    r = scan_files({"requirements.txt": "flask\nnumpy\npytest\n", "a.py": "import flask\n"})
    deps = [f["title"] for f in r["findings"] if f["rule_id"] == "SLOP-UNUSED-DEPENDENCY"]
    assert deps == ["Dependency `numpy` is never imported"]


def test_unknown_language_reported(scan_files):
    r = scan_files({"a.py": "x = 1\n", "weird.xyz": "hello"})
    assert any(u["extension"] == ".xyz" for u in r["languages"]["unsupported"])
