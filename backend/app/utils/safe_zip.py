"""Hardened ZIP extraction for untrusted archives.

Protects against: path traversal ("zip slip"), absolute paths, symlinks, zip bombs
(entry count, declared size, *actual* streamed size, compression ratio) and writes
only into the destination directory. Nothing extracted is ever executed.
"""
from __future__ import annotations

import os
import stat
import zipfile
from pathlib import PurePosixPath

from ..config import IGNORED_DIRS


class UnsafeArchiveError(ValueError):
    """Raised when an archive violates a safety limit."""


MAX_RATIO = 200  # compressed -> uncompressed ratio considered a bomb (for entries > 1 MB)


def _clean_name(name: str) -> PurePosixPath | None:
    name = name.replace("\\", "/")
    if not name or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchiveError(f"Absolute path in archive: {name!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"Path traversal attempt in archive: {name!r}")
    if "\x00" in name:
        raise UnsafeArchiveError("NUL byte in archive entry name")
    return PurePosixPath(*parts) if parts else None


def safe_extract(zip_path: str, dest: str, *, max_files: int, max_total_bytes: int, max_file_bytes: int) -> dict:
    """Extract `zip_path` into `dest`. Returns stats. Raises UnsafeArchiveError on violations."""
    if not zipfile.is_zipfile(zip_path):
        raise UnsafeArchiveError("File is not a valid ZIP archive")
    dest_real = os.path.realpath(dest)
    stats = {"entries": 0, "extracted": 0, "bytes": 0, "skipped_ignored": 0, "skipped_symlinks": 0,
             "skipped_large": 0}
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > max_files * 4:  # entry table itself is a DoS vector
            raise UnsafeArchiveError(f"Archive has too many entries ({len(infos)})")
        declared = sum(i.file_size for i in infos if not i.is_dir())
        if declared > max_total_bytes:
            raise UnsafeArchiveError(
                f"Archive expands to {declared // (1024 * 1024)} MB, limit is {max_total_bytes // (1024 * 1024)} MB")
        for info in infos:
            stats["entries"] += 1
            rel = _clean_name(info.filename)
            if rel is None:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                stats["skipped_symlinks"] += 1
                continue
            if info.is_dir():
                continue
            if any(part in IGNORED_DIRS for part in rel.parts[:-1]):
                stats["skipped_ignored"] += 1
                continue
            if info.flag_bits & 0x1:
                raise UnsafeArchiveError("Encrypted archives are not supported")
            if info.file_size > 1024 * 1024 and info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise UnsafeArchiveError(f"Suspicious compression ratio for {rel} (possible zip bomb)")
            if stats["extracted"] >= max_files:
                raise UnsafeArchiveError(f"Archive contains more than {max_files} files")
            if info.file_size > max_file_bytes:
                stats["skipped_large"] += 1
                continue
            target = os.path.realpath(os.path.join(dest_real, *rel.parts))
            if os.path.commonpath([dest_real, target]) != dest_real:
                raise UnsafeArchiveError(f"Path traversal attempt in archive: {info.filename!r}")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    stats["bytes"] += len(chunk)
                    # Enforce limits on bytes actually produced, not just the declared header.
                    if written > max_file_bytes or stats["bytes"] > max_total_bytes:
                        raise UnsafeArchiveError("Archive exceeded the decompression-size limit")
                    out.write(chunk)
            stats["extracted"] += 1
    return stats
