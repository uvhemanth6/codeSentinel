"""Scan job orchestration: ingestion from ZIP / GitHub / bundled sample, execution, cleanup."""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
import time

from ..config import Config, merged_settings
from . import github
from .pipeline import STAGE_LABELS, run_pipeline
from .store import Store
from ..utils.safe_zip import UnsafeArchiveError, safe_extract

log = logging.getLogger("codesentinel")
SAMPLES = {"python_project": "Python · Flask", "java_project": "Java · Spring Boot", "javascript_project": "JavaScript · Express"}
_SEM = threading.Semaphore(2)


def _unwrap(root: str) -> str:
    """GitHub/zip archives usually wrap everything in one folder; scan inside it for clean paths."""
    entries = [e for e in os.listdir(root) if e not in ("__MACOSX",)]
    if len(entries) == 1 and os.path.isdir(os.path.join(root, entries[0])):
        return os.path.join(root, entries[0])
    return root


class ScanJob:
    def __init__(self, store: Store, config, scan_id: str, kind: str, payload: dict):
        self.store, self.config, self.id, self.kind, self.payload = store, config, scan_id, kind, payload
        self.stages = [{"key": k, "label": label, "status": "pending", "detail": "", "started": None, "ended": None}
                       for k, label in STAGE_LABELS]

    def progress(self, key: str, status: str, detail: str = "") -> None:
        for s in self.stages:
            if s["key"] == key:
                if status == "running" and s["started"] is None:
                    s["started"] = time.time()
                if status == "done":
                    s["started"] = s["started"] or time.time()
                    s["ended"] = time.time()
                s["status"], s["detail"] = status, detail
        self.store.update_stage(self.id, self.stages, key, "running")

    def run(self) -> None:
        with _SEM:
            self._run()

    def _run(self) -> None:
        tmp_root = str(Config.DATA_DIR / "tmp")
        os.makedirs(tmp_root, exist_ok=True)
        work = tempfile.mkdtemp(prefix=f"scan_{self.id}_", dir=tmp_root)
        result, error = None, None
        try:
            self.progress("ingestion", "running", "")
            ingestion: dict = {}
            meta = {"scan_id": self.id, "source_type": self.kind, "started_at": time.time()}
            limits = dict(max_files=self.config["MAX_FILES"], max_total_bytes=self.config["MAX_UNCOMPRESSED_MB"] * 1024 * 1024,
                          max_file_bytes=self.config["MAX_FILE_KB"] * 1024)
            if self.kind == "zip":
                dest = os.path.join(work, "src")
                os.makedirs(dest)
                ingestion = safe_extract(self.payload["zip_path"], dest, **limits)
                meta["source_name"] = self.payload["filename"]
                root = _unwrap(dest)
            elif self.kind == "github":
                dest = os.path.join(work, "src")
                os.makedirs(dest)
                info = github.retrieve(self.payload["url"], dest, timeout=self.config["GITHUB_TIMEOUT"],
                                       max_archive_bytes=self.config["MAX_UPLOAD_MB"] * 1024 * 1024, **limits)
                ingestion = {**info["extract"], "method": info["method"]}
                meta.update(source_name=f"{info['owner']}/{info['repo']}", repository=info["url"], ref=info["ref"],
                            repo_metadata=info["metadata"])
                root = _unwrap(dest)
            elif self.kind == "sample":
                name = self.payload["name"]
                root = str((Config.SAMPLES_DIR / name).resolve())
                meta["source_name"] = f"sample:{name}"
                ingestion = {"method": "bundled sample project (read in place)"}
            else:
                raise ValueError("unknown scan kind")
            settings = merged_settings(self.store.get_settings_overrides())
            result = run_pipeline(root, settings, meta, self.progress, ingestion, limits["max_file_bytes"])
        except (UnsafeArchiveError, github.GitHubError, ValueError) as e:
            error = str(e)
        except Exception as e:  # noqa: BLE001
            log.exception("scan %s crashed", self.id)
            error = f"Internal error while scanning ({e.__class__.__name__})"
        finally:
            shutil.rmtree(work, ignore_errors=True)
            if self.kind == "zip":
                try:
                    os.unlink(self.payload["zip_path"])
                except OSError:
                    pass
        if error:
            for s in self.stages:
                if s["status"] == "running":
                    s["status"], s["detail"] = "failed", error
        self.store.finish_scan(self.id, result, error, self.stages)


def start_scan(app, kind: str, name: str, source_ref: str, payload: dict, options: dict) -> str:
    store: Store = app.extensions["store"]
    sid = store.create_scan(name, kind, source_ref, options)
    job = ScanJob(store, app.config, sid, kind, payload)
    if app.config.get("SCAN_SYNC"):
        job.run()
    else:
        threading.Thread(target=job.run, name=f"scan-{sid}", daemon=True).start()
    return sid
