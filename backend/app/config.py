"""Central configuration: environment limits and default (user-tunable) settings."""
from __future__ import annotations

import copy
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    DATA_DIR = Path(os.environ.get("CS_DATA_DIR", BACKEND_DIR / "data")).resolve()
    DB_PATH = None  # derived in create_app
    MAX_UPLOAD_MB = _int("CS_MAX_UPLOAD_MB", 50)
    MAX_FILES = _int("CS_MAX_FILES", 5000)
    MAX_UNCOMPRESSED_MB = _int("CS_MAX_UNCOMPRESSED_MB", 200)
    MAX_FILE_KB = _int("CS_MAX_FILE_KB", 1024)
    GITHUB_TIMEOUT = _int("CS_GITHUB_TIMEOUT_SECONDS", 60)
    CORS_ORIGINS = [o.strip() for o in os.environ.get(
        "CS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]
    SCAN_SYNC = False  # tests run scans inline
    SAMPLES_DIR = PROJECT_DIR / "sample_projects"
    SEMGREP_RULES = BACKEND_DIR / "rules" / "semgrep_rules.yml"
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    GEMINI_TIMEOUT = _int("GEMINI_TIMEOUT_SECONDS", 45)


# Directories / files never analysed.
IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", "venv", ".venv", "env",
    ".mypy_cache", ".pytest_cache", ".tox", ".idea", ".vscode", ".gradle", ".next",
    ".nuxt", "coverage", "target", "out", ".svn", ".hg", "bower_components", "vendor",
    "site-packages", ".terraform",
}
IGNORED_SUFFIXES = (".min.js", ".min.css", ".map", ".pyc", ".class", ".jar", ".lock",
                    ".egg-info", ".bundle.js", "_pb2.py", ".pb.go")
IGNORED_FILENAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
                     "Pipfile.lock", "composer.lock", "Cargo.lock", "gradlew", "gradlew.bat"}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".pdf", ".zip",
    ".gz", ".tar", ".tgz", ".7z", ".rar", ".bz2", ".xz", ".exe", ".dll", ".so", ".dylib",
    ".bin", ".o", ".a", ".obj", ".class", ".jar", ".war", ".ear", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm",
    ".psd", ".sqlite", ".db", ".pyc", ".pyd", ".wasm", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".iso", ".dmg",
}

DEFAULT_SETTINGS = {
    # Overall health = weighted mean of the four dimension scores (weights are normalised).
    "weights": {"security": 0.40, "quality": 0.20, "completeness": 0.20, "maintainability": 0.20},
    # Penalty points per finding by severity.
    "severity_points": {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0},
    # Confidence multipliers: a "low confidence" heuristic counts for less than a verified match.
    "confidence_factor": {"high": 1.0, "medium": 0.75, "low": 0.5},
    # Dimension score = 100 * exp(-points / (norm * (1 + KLOC * size_factor)))
    "norms": {"security": 30, "quality": 25, "completeness": 25, "maintainability": 25, "slop": 10},
    "size_factor": 0.5,
    "thresholds": {
        "long_function_lines": 60,
        "very_long_function_lines": 120,
        "max_complexity": 10,
        "very_high_complexity": 20,
        "max_nesting": 4,
        "max_params": 7,
        "duplicate_window_lines": 6,
        "min_duplicate_function_lines": 6,
    },
}


def merged_settings(overrides: dict | None) -> dict:
    """Deep-merge user overrides over the defaults (unknown keys are ignored)."""
    out = copy.deepcopy(DEFAULT_SETTINGS)
    for section, values in (overrides or {}).items():
        if section in out and isinstance(out[section], dict) and isinstance(values, dict):
            for k, v in values.items():
                if k in out[section] and isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[section][k] = v
        elif section == "size_factor" and isinstance(values, (int, float)):
            out[section] = float(values)
    return out
