"""Stage 4: project structure + framework detection. Architecture-agnostic: only observes, never requires."""
from __future__ import annotations

import json
import re
from collections import Counter

from ..models.source import ProjectContext

MANIFESTS = ("requirements.txt", "pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
             "Pipfile", "setup.py", "Dockerfile", "docker-compose.yml", "docker-compose.yaml")


def collect_manifests(ctx: ProjectContext) -> None:
    for f in ctx.files:
        base = f.rel.rsplit("/", 1)[-1]
        if base in MANIFESTS and f.rel.count("/") <= 3:
            ctx.manifests[f.rel] = f.text


def detect_frameworks(ctx: ProjectContext) -> list[str]:
    found: set[str] = set()
    manifest_text = "\n".join(ctx.manifests.values()).lower()
    for f in ctx.files:
        if f.lang_name == "Python":
            t = f.text
            if re.search(r"^\s*(from|import)\s+flask\b", t, re.M):
                found.add("Flask")
            if re.search(r"^\s*(from|import)\s+django\b", t, re.M):
                found.add("Django")
            if re.search(r"^\s*(from|import)\s+fastapi\b", t, re.M):
                found.add("FastAPI")
        elif f.lang_name == "Java":
            if "org.springframework" in f.text:
                found.add("Spring Boot" if "SpringBootApplication" in f.text or "spring-boot" in manifest_text
                          else "Spring")
        elif f.lang_name in ("JavaScript", "TypeScript"):
            t = f.text
            if re.search(r"""(require\(\s*['"]express['"]\s*\)|from\s+['"]express['"])""", t):
                found.add("Express")
            if re.search(r"""from\s+['"]react['"]|require\(\s*['"]react['"]\s*\)""", t):
                found.add("React")
    if "flask" in manifest_text:
        found.add("Flask")
    if "django" in manifest_text:
        found.add("Django")
    if "spring-boot" in manifest_text:
        found.add("Spring Boot")
    for rel, text in ctx.manifests.items():
        if rel.endswith("package.json"):
            try:
                pkg = json.loads(text)
            except ValueError:
                continue
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for dep, name in (("express", "Express"), ("react", "React"), ("next", "Next.js"), ("vue", "Vue"),
                              ("@angular/core", "Angular")):
                if dep in deps:
                    found.add(name)
            found.add("Node.js")
    if any(f.lang_name in ("JavaScript", "TypeScript") and re.search(r"\brequire\(|process\.env", f.text)
           for f in ctx.files):
        found.add("Node.js")
    return sorted(found)


def analyze_structure(ctx: ProjectContext) -> dict:
    dirs = Counter()
    for f in ctx.files:
        parts = f.rel.split("/")
        if len(parts) > 1:
            dirs[parts[0]] += 1
    names = {f.rel.lower() for f in ctx.files}
    has_tests = any(f.is_test for f in ctx.files)
    all_files_with_skipped = names | {s["file"].lower() for s in ctx.skipped}
    has_readme = any(n.rsplit("/", 1)[-1].startswith("readme") for n in all_files_with_skipped)
    top = [{"path": d, "files": c} for d, c in dirs.most_common(12)]
    depth = max((f.rel.count("/") for f in ctx.files), default=0)
    entry_points = [f.rel for f in ctx.files if re.search(
        r"(^|/)(main|app|index|server|manage|run|__main__)\.(py|js|ts|java|jsx|tsx)$", f.rel, re.I)][:10]
    return {
        "top_level": top,
        "max_depth": depth,
        "has_tests": has_tests,
        "has_readme": has_readme,
        "manifests": sorted(ctx.manifests),
        "entry_points": entry_points,
        "frameworks": ctx.frameworks,
    }
