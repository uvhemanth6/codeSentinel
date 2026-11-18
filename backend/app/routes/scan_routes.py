import os
import re
import tempfile

from flask import Blueprint, Response, current_app, jsonify, request

from ..config import Config
from ..models.finding import SEVERITY_RANK, CONFIDENCE_RANK
from ..services import github, report
from ..services.runner import SAMPLES, start_scan

bp = Blueprint("scans", __name__, url_prefix="/api")

SORTS = {
    "priority": lambda f: (-f.get("priority", 0), f["file"], f.get("line") or 0),
    "severity": lambda f: (SEVERITY_RANK[f["severity"]], -f.get("priority", 0)),
    "file": lambda f: (f["file"], f.get("line") or 0),
    "confidence": lambda f: (CONFIDENCE_RANK[f["confidence"]], SEVERITY_RANK[f["severity"]]),
}


def _store():
    return current_app.extensions["store"]


def _ai_flag(options: dict) -> dict:
    return {"ai_consent": bool(options.get("ai_consent"))}


def _public_scan(scan: dict) -> dict:
    out = {k: v for k, v in scan.items() if k != "result"}
    res = scan.get("result")
    if res:
        out["result"] = {k: v for k, v in res.items() if k not in ("findings", "files")}
        out["result"]["finding_count"] = len(res["findings"])
        out["result"]["file_count"] = len(res["files"])
    return out


@bp.post("/scans/upload")
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify(error="Attach a ZIP file in the 'file' field"), 400
    filename = re.sub(r"[^\w.\- ]", "_", os.path.basename(f.filename))[:100]
    if not filename.lower().endswith(".zip"):
        return jsonify(error="Only .zip archives are supported"), 400
    tmp_dir = Config.DATA_DIR / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(suffix=".zip", dir=tmp_dir)
    os.close(fd)
    try:
        f.save(path)
    except Exception:  # noqa: BLE001
        os.unlink(path)
        return jsonify(error="Could not store the uploaded file"), 400
    sid = start_scan(current_app._get_current_object(), "zip", request.form.get("name") or filename,
                     filename, {"zip_path": path, "filename": filename}, _ai_flag({"ai_consent": request.form.get("ai_consent") == "true"}))
    return jsonify(id=sid), 202


@bp.post("/scans/github")
def scan_github():
    body = request.get_json(silent=True) or {}
    try:
        info = github.parse_github_url(body.get("url", ""))
    except github.GitHubError as e:
        return jsonify(error=str(e)), 400
    sid = start_scan(current_app._get_current_object(), "github", f"{info['owner']}/{info['repo']}", info["url"],
                     {"url": info["url"]}, _ai_flag(body))
    return jsonify(id=sid), 202


@bp.post("/scans/sample")
def scan_sample():
    name = (request.get_json(silent=True) or {}).get("name")
    if name not in SAMPLES:
        return jsonify(error="Unknown sample project"), 400
    sid = start_scan(current_app._get_current_object(), "sample", f"Sample: {SAMPLES[name]}", name, {"name": name}, {})
    return jsonify(id=sid), 202


@bp.get("/scans")
def list_scans():
    return jsonify(scans=_store().list_scans())


@bp.get("/scans/<sid>")
def get_scan(sid):
    scan = _store().get_scan(sid)
    if not scan:
        return jsonify(error="Scan not found"), 404
    return jsonify(_public_scan(scan))


@bp.delete("/scans/<sid>")
def delete_scan(sid):
    if not _store().delete_scan(sid):
        return jsonify(error="Scan not found"), 404
    return jsonify(deleted=True)


@bp.get("/scans/<sid>/findings")
def findings(sid):
    scan = _store().get_scan(sid)
    if not scan or not scan.get("result"):
        return jsonify(error="Scan not found or not finished"), 404
    items = scan["result"]["findings"]
    reviews = _store().reviews(sid)
    a = request.args

    def multi(name):
        v = a.get(name)
        return {x for x in v.split(",") if x} if v else None
    cats, sevs, subs, srcs = multi("category"), multi("severity"), multi("subcategory"), multi("source")
    verifs = multi("verification")
    q = (a.get("q") or "").strip().lower()
    reviewed = a.get("reviewed")
    file_filter = a.get("file")
    base = [f for f in items if (not cats or f["category"] in cats) and (not file_filter or f["file"] == file_filter)]
    facets = {"severity": {}, "subcategory": {}, "source": {}, "verification": {}}
    for f in base:
        facets["severity"][f["severity"]] = facets["severity"].get(f["severity"], 0) + 1
        facets["subcategory"][f["subcategory"]] = facets["subcategory"].get(f["subcategory"], 0) + 1
        facets["verification"][f["verification"]] = facets["verification"].get(f["verification"], 0) + 1
        for s in f["detected_by"]:
            facets["source"][s] = facets["source"].get(s, 0) + 1
    out = []
    for f in base:
        rv = reviews.get(f["id"], {"reviewed": False, "note": ""})
        if sevs and f["severity"] not in sevs:
            continue
        if subs and f["subcategory"] not in subs:
            continue
        if srcs and not (set(f["detected_by"]) & srcs):
            continue
        if verifs and f["verification"] not in verifs:
            continue
        if reviewed in ("true", "false") and rv["reviewed"] != (reviewed == "true"):
            continue
        if q and q not in " ".join([f["title"], f["file"], f["rule_id"], f["evidence"], f["explanation"], f["id"]]).lower():
            continue
        out.append({**f, "review": rv})
    out.sort(key=SORTS.get(a.get("sort", "priority"), SORTS["priority"]))
    if a.get("order") == "desc" and a.get("sort") in ("file",):
        out.reverse()
    try:
        limit = max(1, min(int(a.get("limit", 200)), 1000))
        offset = max(0, int(a.get("offset", 0)))
    except ValueError:
        limit, offset = 200, 0
    return jsonify(total=len(out), items=out[offset:offset + limit], facets=facets, offset=offset, limit=limit,
                   reviewed_total=sum(1 for f in base if reviews.get(f["id"], {}).get("reviewed")), base_total=len(base))


@bp.patch("/scans/<sid>/findings/<fid>/review")
def review(sid, fid):
    scan = _store().get_scan(sid)
    if not scan or not scan.get("result"):
        return jsonify(error="Scan not found"), 404
    if not any(f["id"] == fid for f in scan["result"]["findings"]):
        return jsonify(error="Finding not found"), 404
    body = request.get_json(silent=True) or {}
    reviewed = body.get("reviewed")
    if not isinstance(reviewed, bool):
        return jsonify(error="'reviewed' must be a boolean"), 400
    note = body.get("note", "")
    if not isinstance(note, str):
        return jsonify(error="'note' must be a string"), 400
    _store().set_review(sid, fid, reviewed, note)
    return jsonify(finding_id=fid, reviewed=reviewed, note=note[:1000])


@bp.get("/scans/<sid>/files")
def files(sid):
    scan = _store().get_scan(sid)
    if not scan or not scan.get("result"):
        return jsonify(error="Scan not found"), 404
    r = scan["result"]
    return jsonify(files=r["files"], skipped=r["skipped"], unsupported=r["languages"]["unsupported"])


@bp.get("/scans/<sid>/report")
def get_report(sid):
    scan = _store().get_scan(sid)
    if not scan or not scan.get("result"):
        return jsonify(error="Scan not found"), 404
    fmt = request.args.get("format", "json")
    reviews = _store().reviews(sid)
    safe = re.sub(r"[^\w.-]", "_", scan["name"])[:50] or "scan"
    if fmt == "md":
        body, mime = report.to_markdown(scan, reviews), "text/markdown"
    elif fmt == "html":
        body, mime = report.to_html(scan, reviews), "text/html"
    elif fmt == "json":
        body, mime = report.to_json(scan, reviews), "application/json"
    else:
        return jsonify(error="format must be json, md or html"), 400
    resp = Response(body, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="codesentinel-{safe}.{fmt}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.get("/dashboard")
def dashboard():
    scans = _store().list_scans(50)
    done = [s for s in scans if s["status"] == "completed" and s["summary"]]
    latest = None
    if done:
        full = _store().get_scan(done[0]["id"])
        r = full["result"]
        latest = {"scan_id": full["id"], "name": full["name"], "created_at": full["created_at"],
                  "scores": r["summary"]["scores"], "languages": r["languages"]["languages"],
                  "frameworks": r["structure"].get("frameworks", []), "files_scanned": r["summary"]["files_scanned"],
                  "code_lines": r["summary"]["code_lines"],
                  "by_category": {c: sum(1 for f in r["findings"] if f["category"] == c)
                                  for c in ("Security", "Code Slop", "Coding Gaps", "Loose Ends")}}
    return jsonify(latest=latest, recent=scans[:8], total_scans=len(scans), completed_scans=len(done))
