"""Safe retrieval of public GitHub repositories.

SSRF / local-file protections:
  * Only `https://github.com/<owner>/<repo>` URLs are accepted (strict regex, no userinfo,
    ports, IPs, other hosts, query strings or `file://`).
  * Network requests go only to fixed GitHub hosts that WE construct from the validated
    owner/repo - the user never supplies a request URL.
  * Redirects are followed manually and only to an allow-list of GitHub hosts over https.
  * Downloads are streamed with a hard size cap and timeout, then extracted with the same
    hardened extractor used for uploads. Nothing is executed (no hooks, no build scripts).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..utils.safe_zip import safe_extract

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?|[A-Za-z0-9]"
_URL_RE = re.compile(
    rf"^https://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{{0,38}}))/(?P<repo>{_NAME}?)"
    rf"(?:\.git)?/?(?:/tree/(?P<ref>[A-Za-z0-9_./-]{{1,100}}))?$")
ALLOWED_REDIRECT_HOSTS = ("github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
                          "raw.githubusercontent.com")


class GitHubError(ValueError):
    pass


def parse_github_url(url: str) -> dict:
    """Validate and decompose a GitHub repository URL. Raises GitHubError."""
    if not isinstance(url, str) or not url.strip():
        raise GitHubError("A GitHub repository URL is required")
    url = url.strip()
    if len(url) > 200 or any(c in url for c in " \t\r\n\\@?#") or ".." in url:
        raise GitHubError("Invalid repository URL")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise GitHubError("Only https://github.com/<owner>/<repo> URLs are supported")
    if parsed.port is not None or parsed.username or parsed.password:
        raise GitHubError("Ports and credentials are not allowed in repository URLs")
    if (parsed.hostname or "").lower() not in ("github.com", "www.github.com"):
        raise GitHubError("Only public repositories hosted on github.com are supported")
    m = _URL_RE.match(url)
    if not m or not m.group("repo"):
        raise GitHubError("URL must look like https://github.com/<owner>/<repo>")
    repo = m.group("repo")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo in (".", "..") or repo.startswith("."):
        raise GitHubError("Invalid repository name")
    return {"owner": m.group("owner"), "repo": repo, "ref": m.group("ref"),
            "url": f"https://github.com/{m.group('owner')}/{repo}"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _request(url: str, timeout: int, accept: str = "application/vnd.github+json", max_redirects: int = 4):
    for _ in range(max_redirects + 1):
        host = (urlparse(url).hostname or "").lower()
        if urlparse(url).scheme != "https" or host not in ALLOWED_REDIRECT_HOSTS:
            raise GitHubError("Refusing to contact a non-GitHub host")
        req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "CodeSentinel-Scanner"})
        try:
            return _opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                url = e.headers["Location"]
                continue
            if e.code == 404:
                raise GitHubError("Repository not found or not public") from e
            if e.code in (403, 429):
                raise GitHubError("GitHub rate limit reached - try again later") from e
            raise GitHubError(f"GitHub returned HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise GitHubError(f"Could not reach GitHub: {getattr(e, 'reason', e)}") from e
    raise GitHubError("Too many redirects")


def fetch_metadata(owner: str, repo: str, timeout: int) -> dict:
    with _request(f"https://api.github.com/repos/{owner}/{repo}", timeout) as resp:
        data = json.loads(resp.read(1024 * 1024).decode("utf-8", "replace"))
    if data.get("private"):
        raise GitHubError("Private repositories are not supported")
    return {
        "full_name": data.get("full_name"), "description": data.get("description"),
        "default_branch": data.get("default_branch", "main"), "stars": data.get("stargazers_count"),
        "language": data.get("language"), "size_kb": data.get("size"), "license": (data.get("license") or {}).get("spdx_id"),
        "updated_at": data.get("pushed_at"), "html_url": data.get("html_url"), "fork": data.get("fork"),
        "archived": data.get("archived"),
    }


def _download_archive(owner: str, repo: str, ref: str, dest_zip: str, timeout: int, max_bytes: int) -> None:
    with _request(f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref}", timeout, accept="*/*") as resp:
        total = 0
        with open(dest_zip, "wb") as out:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise GitHubError("Repository archive exceeds the size limit")
                out.write(chunk)


def _shallow_clone(url: str, ref: str | None, dest: str, timeout: int) -> None:
    if not shutil.which("git"):
        raise GitHubError("git is not available for the clone fallback")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "core.symlinks=false", "clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url + ".git", dest]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        raise GitHubError("Clone timed out") from e
    except subprocess.CalledProcessError as e:
        raise GitHubError("git clone failed") from e
    shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)


def retrieve(url: str, dest_dir: str, *, timeout: int, max_files: int, max_total_bytes: int,
             max_file_bytes: int, max_archive_bytes: int) -> dict:
    """Validate `url`, download into `dest_dir`, return metadata. Caller cleans up `dest_dir`."""
    info = parse_github_url(url)
    meta: dict = {}
    try:
        meta = fetch_metadata(info["owner"], info["repo"], timeout)
    except GitHubError as e:
        if "not found" in str(e).lower() or "private" in str(e).lower():
            raise
        meta = {}  # metadata is best effort; the archive/clone step reports real failures
    if meta.get("size_kb") and meta["size_kb"] * 1024 > max_archive_bytes * 4:
        raise GitHubError("Repository is larger than the configured size limit")
    ref = info["ref"] or meta.get("default_branch") or "HEAD"
    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip", dir=os.path.dirname(dest_dir))
    tmp_zip.close()
    try:
        try:
            _download_archive(info["owner"], info["repo"], ref, tmp_zip.name, timeout, max_archive_bytes)
            stats = safe_extract(tmp_zip.name, dest_dir, max_files=max_files, max_total_bytes=max_total_bytes,
                                 max_file_bytes=max_file_bytes)
            method = "archive"
        except GitHubError:
            shutil.rmtree(dest_dir, ignore_errors=True)
            os.makedirs(dest_dir, exist_ok=True)
            _shallow_clone(info["url"], info["ref"], dest_dir, timeout)
            stats, method = {}, "shallow-clone"
    finally:
        try:
            os.unlink(tmp_zip.name)
        except OSError:
            pass
    return {"owner": info["owner"], "repo": info["repo"], "url": info["url"], "ref": ref, "method": method,
            "metadata": meta, "extract": stats}
