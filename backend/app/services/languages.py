"""Extensible language registry.

Adding a language = one `register_language(...)` call. The pipeline, the generic
analyzers (secrets, loose ends, duplication) and the UI pick it up automatically.
`support` is honest about depth: "full" languages have dedicated analyzers,
"partial" languages only get language-agnostic analyzers.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Language:
    name: str
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()
    comment_style: str = "none"   # c | hash | sql | html | css | none
    support: str = "partial"      # full | partial
    kind: str = "code"            # code | config | markup | data
    analyzers: tuple[str, ...] = ()  # descriptive: which specialised analyzers apply


_REGISTRY: dict[str, Language] = {}
_BY_EXT: dict[str, Language] = {}
_BY_NAME: dict[str, Language] = {}


def register_language(lang: Language) -> None:
    _REGISTRY[lang.name] = lang
    for ext in lang.extensions:
        _BY_EXT[ext.lower()] = lang
    for fn in lang.filenames:
        _BY_NAME[fn.lower()] = lang


def all_languages() -> list[Language]:
    return list(_REGISTRY.values())


def get_language(name: str) -> Language | None:
    return _REGISTRY.get(name)


def detect_language(rel_path: str) -> Language | None:
    p = PurePosixPath(rel_path)
    by_name = _BY_NAME.get(p.name.lower())
    if by_name:
        return by_name
    suffix = p.suffix.lower()
    return _BY_EXT.get(suffix)


# Documentation / data files that are intentionally not analysed.
IGNORED_TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".csv", ".svg", ".lock", ".log", ".license", ".gitignore",
                           ".gitattributes", ".editorconfig", ".tsv"}

# --- Full support ---------------------------------------------------------------
register_language(Language("Python", (".py", ".pyw"), (), "hash", "full", "code",
                           ("python-ast", "bandit", "semgrep", "patterns", "slop", "gaps")))
register_language(Language("Java", (".java",), (), "c", "full", "code", ("patterns", "slop", "gaps", "semgrep")))
register_language(Language("JavaScript", (".js", ".jsx", ".mjs", ".cjs"), (), "c", "full", "code",
                           ("patterns", "slop", "gaps", "semgrep")))
register_language(Language("TypeScript", (".ts", ".tsx"), (), "c", "full", "code",
                           ("patterns", "slop", "gaps", "semgrep")))
register_language(Language("HTML", (".html", ".htm", ".xhtml", ".vue"), (), "html", "full", "markup", ("html",)))
register_language(Language("CSS", (".css", ".scss", ".less"), (), "css", "full", "markup", ("css",)))
register_language(Language("SQL", (".sql",), (), "sql", "full", "code", ("sql",)))
register_language(Language("JSON", (".json",), (".babelrc",), "none", "full", "config", ("json",)))
register_language(Language("YAML", (".yml", ".yaml"), (), "hash", "full", "config", ("yaml",)))

# --- Partial support (generic analyzers only) -----------------------------------
register_language(Language("Go", (".go",), (), "c", "partial", "code"))
register_language(Language("Rust", (".rs",), (), "c", "partial", "code"))
register_language(Language("PHP", (".php",), (), "c", "partial", "code"))
register_language(Language("Ruby", (".rb",), ("Gemfile", "Rakefile"), "hash", "partial", "code"))
register_language(Language("C", (".c", ".h"), (), "c", "partial", "code"))
register_language(Language("C++", (".cpp", ".cc", ".cxx", ".hpp"), (), "c", "partial", "code"))
register_language(Language("C#", (".cs",), (), "c", "partial", "code"))
register_language(Language("Kotlin", (".kt", ".kts"), (), "c", "partial", "code"))
register_language(Language("Swift", (".swift",), (), "c", "partial", "code"))
register_language(Language("Shell", (".sh", ".bash", ".zsh"), (), "hash", "partial", "code"))
register_language(Language("Properties", (".properties", ".ini", ".cfg", ".conf", ".toml"), (".env", "requirements.txt", "requirements-dev.txt", "constraints.txt", "Pipfile"),
                           "hash", "partial", "config"))
register_language(Language("XML", (".xml", ".gradle"), ("pom.xml",), "html", "partial", "config"))
register_language(Language("Dockerfile", (), ("dockerfile",), "hash", "partial", "config"))
