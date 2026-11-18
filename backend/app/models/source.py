"""SourceFile / ProjectContext passed to every analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..services.languages import Language
from ..utils.code_view import code_views


@dataclass
class SourceFile:
    abs_path: str
    rel: str
    language: Language | None
    text: str
    size: int
    _views: tuple | None = field(default=None, repr=False)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def lang_name(self) -> str | None:
        return self.language.name if self.language else None

    def views(self) -> tuple[str, str, list[tuple[int, str]]]:
        if self._views is None:
            style = self.language.comment_style if self.language else "none"
            self._views = code_views(self.text, style, python=self.lang_name == "Python")
        return self._views

    @property
    def nocomment(self) -> str:
        return self.views()[0]

    @property
    def blanked(self) -> str:
        return self.views()[1]

    @property
    def comments(self) -> list[tuple[int, str]]:
        return self.views()[2]

    @property
    def is_test(self) -> bool:
        p = "/" + self.rel.lower()
        name = p.rsplit("/", 1)[-1]
        return ("/test/" in p or "/tests/" in p or "/__tests__/" in p or "/spec/" in p or "/e2e/" in p
                or name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".test.ts", ".test.tsx",
                                                              ".spec.js", ".spec.ts", "test.java", "tests.java",
                                                              ".test.jsx", ".spec.tsx")))

    @property
    def is_example(self) -> bool:
        p = "/" + self.rel.lower()
        return any(s in p for s in ("/examples/", "/example/", "/fixtures/", "/mocks/", "/docs/"))


@dataclass
class ProjectContext:
    root: str
    files: list[SourceFile]
    settings: dict[str, Any]
    frameworks: list[str] = field(default_factory=list)
    tools: dict[str, Any] = field(default_factory=dict)
    skipped: list[dict[str, str]] = field(default_factory=list)
    manifests: dict[str, str] = field(default_factory=dict)  # rel path -> text

    @property
    def threshold(self) -> dict[str, Any]:
        return self.settings["thresholds"]

    def code_files(self, *languages: str) -> list[SourceFile]:
        names = set(languages)
        return [f for f in self.files if f.language and (not names or f.lang_name in names)]
