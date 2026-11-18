import os

import pytest

from app.services import github
from app.services.discovery import discover
from app.utils.safe_zip import UnsafeArchiveError, safe_extract
from conftest import make_zip

LIM = dict(max_files=100, max_total_bytes=5_000_000, max_file_bytes=1_000_000)


def _extract(tmp_path, data, **lim):
    z = tmp_path / "t.zip"
    z.write_bytes(data)
    dest = tmp_path / "out"
    dest.mkdir(exist_ok=True)
    return safe_extract(str(z), str(dest), **{**LIM, **lim}), dest


def test_extracts_normal_zip_and_skips_ignored(tmp_path):
    stats, dest = _extract(tmp_path, make_zip({"a/b.py": "x=1", "node_modules/x.js": "1", ".git/config": "c"}))
    assert (dest / "a" / "b.py").exists() and not (dest / "node_modules").exists()
    assert stats["skipped_ignored"] == 2


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/abs/evil.py", "..\\evil.py", "C:/evil.py"])
def test_path_traversal_rejected(tmp_path, name):
    with pytest.raises(UnsafeArchiveError):
        _extract(tmp_path, make_zip({name: "x"}))
    assert not (tmp_path / "evil.py").exists()


def test_symlink_entries_skipped(tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
        z.writestr("ok.py", "x=1")
    stats, dest = _extract(tmp_path, buf.getvalue())
    assert stats["skipped_symlinks"] == 1 and not (dest / "link").exists()


def test_size_and_count_limits(tmp_path):
    with pytest.raises(UnsafeArchiveError):
        _extract(tmp_path, make_zip({f"f{i}.py": "x" for i in range(10)}), max_files=5)
    with pytest.raises(UnsafeArchiveError):
        _extract(tmp_path, make_zip({"big.txt": "a" * 2_000_000}), max_total_bytes=1_000_000)


def test_zip_bomb_ratio_rejected(tmp_path):
    with pytest.raises(UnsafeArchiveError):
        _extract(tmp_path, make_zip({"bomb.txt": b"\0" * 5_000_000}), max_total_bytes=10_000_000, max_file_bytes=10_000_000)


def test_not_a_zip(tmp_path):
    with pytest.raises(UnsafeArchiveError):
        _extract(tmp_path, b"not a zip")


def test_discovery_excludes_binary_generated_and_large(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02" * 100)
    (tmp_path / "gen.py").write_text("# Auto-generated file. DO NOT EDIT\nx=1\n")
    (tmp_path / "app.min.js").write_text("var a=1;")
    (tmp_path / "README.md").write_text("# hi")
    (tmp_path / "big.py").write_text("x=1\n" * 500)
    for d in ("venv", "node_modules", "__pycache__", "dist", "build", ".venv", ".git"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "x.py").write_text("import os\n")
    files, skipped, _ = discover(str(tmp_path), max_file_bytes=1000)
    assert [f.rel for f in files] == ["a.py"]
    reasons = {s["reason"] for s in skipped}
    assert {"binary", "generated file", "generated/lock file", "too large", "documentation/data"} <= reasons


# ---- GitHub URL validation / SSRF -------------------------------------------------
@pytest.mark.parametrize("url", [
    "https://github.com/octocat/Hello-World", "https://github.com/octocat/Hello-World.git",
    "https://github.com/octocat/Hello-World/", "https://www.github.com/a/b", "https://github.com/a/b/tree/main"])
def test_valid_github_urls(url):
    info = github.parse_github_url(url)
    assert info["owner"] and info["repo"]


@pytest.mark.parametrize("url", [
    "", "http://github.com/a/b", "https://evil.com/a/b", "https://github.com.evil.com/a/b",
    "https://github.com@evil.com/a/b", "https://user:pw@github.com/a/b", "https://github.com:8443/a/b",
    "file:///etc/passwd", "ftp://github.com/a/b", "https://127.0.0.1/a/b", "https://localhost/a/b",
    "https://github.com/a", "https://github.com/a/b/../../c", "https://github.com/a/b?x=1", "https://github.com/a/b#x",
    "https://169.254.169.254/latest/meta-data", "https://github.com/a/b c", "javascript:alert(1)",
    "https://github.com//b", "git@github.com:a/b.git", None, 123])
def test_invalid_github_urls_rejected(url):
    with pytest.raises(github.GitHubError):
        github.parse_github_url(url)


def test_redirects_limited_to_github_hosts(monkeypatch):
    with pytest.raises(github.GitHubError):
        github._request("https://evil.example/x", 3)
    with pytest.raises(github.GitHubError):
        github._request("http://api.github.com/x", 3)
