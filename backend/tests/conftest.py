import io
import os
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app  # noqa: E402
from app.config import merged_settings  # noqa: E402
from app.services.pipeline import run_pipeline  # noqa: E402


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    return create_app({"DATA_DIR": tmp_path / "data", "SCAN_SYNC": True, "TESTING": True})


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def scan_files(tmp_path):
    """Write {relpath: source} into a fresh dir and run the real pipeline on it."""
    def _scan(files: dict[str, str]):
        root = tmp_path / "proj"
        root.mkdir(exist_ok=True)
        for rel, src in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(src), encoding="utf-8")
        return run_pipeline(str(root), merged_settings({}), {"source_name": "test"})
    return _scan


def rules(result, category=None):
    return [f["rule_id"] for f in result["findings"] if category is None or f["category"] == category]


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def families(result, category=None):
    return {f["family"] for f in result["findings"] if category is None or f["category"] == category}
