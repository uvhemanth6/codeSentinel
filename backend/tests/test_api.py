import io

import pytest

from conftest import make_zip


def _upload(client, files, name="p.zip", **form):
    data = {"file": (io.BytesIO(make_zip(files)), name), **form}
    return client.post("/api/scans/upload", data=data, content_type="multipart/form-data")


VULN = {"proj/app.py": 'import pickle\nfrom flask import request\ndef f():\n    return pickle.loads(request.data)\n'
                       '# TODO: auth\npassword = "hunter2hunter2"\n',
        "proj/ui.js": "el.innerHTML = location.hash;\nconsole.log('x');\n"}


def test_health(client):
    h = client.get("/api/health").get_json()
    assert h["status"] == "ok" and h["engine"]["security_rules"] > 30
    assert {l["name"] for l in h["languages"]} >= {"Python", "Java", "JavaScript", "TypeScript", "HTML", "CSS", "SQL", "JSON", "YAML"}


def test_upload_scan_end_to_end(client):
    r = _upload(client, VULN)
    assert r.status_code == 202
    sid = r.get_json()["id"]
    scan = client.get(f"/api/scans/{sid}").get_json()
    assert scan["status"] == "completed" and scan["error"] is None
    assert [s["status"] for s in scan["stages"]].count("done") == 14
    res = scan["result"]
    assert res["summary"]["files_scanned"] == 2 and "findings" not in res
    assert res["summary"]["scores"]["overall"] is not None
    assert res["ai"]["deterministic"]["mode"] == "deterministic"
    # extracted files cleaned up
    import os
    tmp = os.path.join(client.application.config["DATA_DIR"], "tmp")
    assert os.listdir(tmp) == []


def test_findings_filters_search_sort_and_review(client):
    sid = _upload(client, VULN).get_json()["id"]
    allf = client.get(f"/api/scans/{sid}/findings").get_json()
    assert allf["total"] >= 4 and allf["facets"]["severity"]
    sec = client.get(f"/api/scans/{sid}/findings?category=Security").get_json()
    assert sec["total"] and all(f["category"] == "Security" for f in sec["items"])
    assert client.get(f"/api/scans/{sid}/findings?severity=critical,high&category=Security").get_json()["total"] >= 1
    q = client.get(f"/api/scans/{sid}/findings?q=pickle").get_json()
    assert q["total"] >= 1 and all("pickle" in str(f).lower() for f in q["items"])
    by_file = client.get(f"/api/scans/{sid}/findings?sort=file").get_json()["items"]
    assert [f["file"] for f in by_file] == sorted(f["file"] for f in by_file)
    fid = allf["items"][0]["id"]
    r = client.patch(f"/api/scans/{sid}/findings/{fid}/review", json={"reviewed": True, "note": "ok"})
    assert r.status_code == 200
    rv = client.get(f"/api/scans/{sid}/findings?reviewed=true").get_json()
    assert rv["total"] == 1 and rv["items"][0]["review"]["note"] == "ok"
    assert client.get(f"/api/scans/{sid}/findings?reviewed=false").get_json()["total"] == allf["total"] - 1
    assert client.patch(f"/api/scans/{sid}/findings/F-nope/review", json={"reviewed": True}).status_code == 404
    assert client.patch(f"/api/scans/{sid}/findings/{fid}/review", json={"reviewed": "yes"}).status_code == 400


def test_reports(client):
    sid = _upload(client, {"a.py": 'x = "<script>alert(1)</script>"\nimport pickle\npickle.loads(b"")  # TODO <b>x</b>\n'}
                  ).get_json()["id"]
    j = client.get(f"/api/scans/{sid}/report?format=json")
    assert j.status_code == 200 and "findings" in j.get_json()
    md = client.get(f"/api/scans/{sid}/report?format=md").get_data(as_text=True)
    assert "# CodeSentinel report" in md and "not a security" in md.lower()
    html = client.get(f"/api/scans/{sid}/report?format=html")
    body = html.get_data(as_text=True)
    assert "<b>x</b>" not in body and "&lt;b&gt;x&lt;/b&gt;" in body  # untrusted code is escaped
    assert html.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get(f"/api/scans/{sid}/report?format=exe").status_code == 400


def test_upload_validation(client):
    assert client.post("/api/scans/upload", data={}, content_type="multipart/form-data").status_code == 400
    r = client.post("/api/scans/upload", data={"file": (io.BytesIO(b"hi"), "a.txt")}, content_type="multipart/form-data")
    assert r.status_code == 400
    sid = client.post("/api/scans/upload", data={"file": (io.BytesIO(b"not a zip"), "a.zip")},
                      content_type="multipart/form-data").get_json()["id"]
    s = client.get(f"/api/scans/{sid}").get_json()
    assert s["status"] == "failed" and "ZIP" in s["error"]


def test_malicious_zip_rejected(client):
    sid = _upload(client, {"../../evil.py": "x"}).get_json()["id"]
    s = client.get(f"/api/scans/{sid}").get_json()
    assert s["status"] == "failed" and "traversal" in s["error"].lower()


def test_upload_size_limit(app):
    app.config["MAX_CONTENT_LENGTH"] = 1000
    c = app.test_client()
    r = c.post("/api/scans/upload", data={"file": (io.BytesIO(b"x" * 5000), "a.zip")}, content_type="multipart/form-data")
    assert r.status_code == 413


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://evil.com/a/b", "file:///etc/passwd", "", "https://127.0.0.1/a/b"])
def test_github_endpoint_rejects_bad_urls(client, url):
    r = client.post("/api/scans/github", json={"url": url})
    assert r.status_code == 400 and "error" in r.get_json()


def test_github_scan_uses_validated_retrieval(client, monkeypatch, tmp_path):
    from app.services import github

    def fake_retrieve(url, dest_dir, **kw):
        (tmp_path / "x").mkdir(exist_ok=True)
        import os
        os.makedirs(os.path.join(dest_dir, "o-r-abc123"), exist_ok=True)
        with open(os.path.join(dest_dir, "o-r-abc123", "a.py"), "w") as f:
            f.write("import pickle\npickle.loads(b'')\n")
        return {"owner": "o", "repo": "r", "url": url, "ref": "main", "method": "archive", "metadata": {"stars": 1}, "extract": {}}
    monkeypatch.setattr(github, "retrieve", fake_retrieve)
    sid = client.post("/api/scans/github", json={"url": "https://github.com/o/r"}).get_json()["id"]
    s = client.get(f"/api/scans/{sid}").get_json()
    assert s["status"] == "completed" and s["result"]["meta"]["repository"] == "https://github.com/o/r"
    f = client.get(f"/api/scans/{sid}/findings").get_json()["items"]
    assert any(x["file"] == "a.py" for x in f)  # wrapper directory unwrapped


def test_github_network_failure_reported(client, monkeypatch):
    from app.services import github
    monkeypatch.setattr(github, "retrieve", lambda *a, **k: (_ for _ in ()).throw(github.GitHubError("Repository not found or not public")))
    sid = client.post("/api/scans/github", json={"url": "https://github.com/o/r"}).get_json()["id"]
    s = client.get(f"/api/scans/{sid}").get_json()
    assert s["status"] == "failed" and "not found" in s["error"]


def test_sample_scans(client):
    assert client.post("/api/scans/sample", json={"name": "../../etc"}).status_code == 400
    for name in ("python_project", "java_project", "javascript_project"):
        sid = client.post("/api/scans/sample", json={"name": name}).get_json()["id"]
        s = client.get(f"/api/scans/{sid}").get_json()
        assert s["status"] == "completed", s["error"]
        assert all(a["error"] is None for a in s["result"]["analyzers"] if a["status"] != "skipped"), s["result"]["analyzers"]
        assert s["result"]["summary"]["scores"]["counts"]["total"] > 10


def test_dashboard_empty_and_filled(client):
    d = client.get("/api/dashboard").get_json()
    assert d["latest"] is None and d["recent"] == []
    sid = _upload(client, VULN).get_json()["id"]
    d = client.get("/api/dashboard").get_json()
    assert d["latest"]["scan_id"] == sid and d["latest"]["scores"]["overall"] is not None and len(d["recent"]) == 1


def test_delete_and_history(client):
    sid = _upload(client, VULN).get_json()["id"]
    assert [s["id"] for s in client.get("/api/scans").get_json()["scans"]] == [sid]
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404
    assert client.get("/api/scans").get_json()["scans"] == []


def test_settings_roundtrip_and_validation(client):
    s = client.get("/api/settings").get_json()
    assert s["settings"]["weights"]["security"] == 0.4 and s["ai"]["configured"] is False
    r = client.put("/api/settings", json={"weights": {"security": 0.1, "quality": 0.3, "completeness": 0.3, "maintainability": 0.3}})
    assert r.status_code == 200 and r.get_json()["settings"]["weights"]["security"] == 0.1
    assert client.put("/api/settings", json={"weights": {"security": -1}}).status_code == 400
    assert client.put("/api/settings", json={"thresholds": {"max_params": "x"}}).status_code == 400
    assert client.put("/api/settings", json={"weights": {"security": 0, "quality": 0, "completeness": 0, "maintainability": 0}}).status_code == 400
    sid = _upload(client, VULN).get_json()["id"]
    assert client.get(f"/api/scans/{sid}").get_json()["result"]["settings"]["weights"]["security"] == 0.1  # snapshot used
    assert client.post("/api/settings/reset").get_json()["settings"]["weights"]["security"] == 0.4


def test_ai_endpoints_without_key_fall_back(client):
    sid = _upload(client, VULN).get_json()["id"]
    p = client.post(f"/api/scans/{sid}/ai/preview", json={"limit": 3}).get_json()
    assert 0 < len(p["payload"]["findings"]) <= 3 and "hunter2hunter2" not in str(p)
    assert "sent" in p["disclosure"].lower()
    r = client.post(f"/api/scans/{sid}/ai/review", json={"consent": True}).get_json()
    assert r["mode"] == "deterministic" and r["fallback_reason"] == "missing_api_key"
    r = client.post(f"/api/scans/{sid}/ai/review", json={}).get_json()
    assert r["fallback_reason"] == "consent_required"
    assert client.post(f"/api/scans/{sid}/ai/review", json={"limit": "x"}).status_code == 400
    assert client.post("/api/scans/nope/ai/review", json={"consent": True}).status_code == 404


def test_ai_review_persisted_with_mock_model(client, monkeypatch):
    import json
    from app.ai import gemini
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    sid = _upload(client, VULN).get_json()["id"]
    fid = client.get(f"/api/scans/{sid}/findings").get_json()["items"][0]["id"]
    monkeypatch.setattr(gemini, "call_gemini", lambda *a: json.dumps({
        "executive_summary": "S", "finding_reviews": [{"finding_id": fid, "technical_implication": "T"}]}))
    r = client.post(f"/api/scans/{sid}/ai/review", json={"consent": True, "limit": 5}).get_json()
    assert r["mode"] == "gemini" and r["verified"] is False
    stored = client.get(f"/api/scans/{sid}").get_json()["result"]["ai"]
    assert stored["gemini"]["review"]["finding_reviews"][0]["finding_id"] == fid
