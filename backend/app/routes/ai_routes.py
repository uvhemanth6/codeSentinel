import time

from flask import Blueprint, current_app, jsonify, request

from ..ai import gemini

bp = Blueprint("ai", __name__, url_prefix="/api")


def _load(sid):
    store = current_app.extensions["store"]
    scan = store.get_scan(sid)
    if not scan or not scan.get("result"):
        return None, None, (jsonify(error="Scan not found or not finished"), 404)
    return store, scan, None


def _params():
    body = request.get_json(silent=True) or {}
    ids = body.get("finding_ids")
    if ids is not None and not (isinstance(ids, list) and all(isinstance(i, str) for i in ids)):
        raise ValueError("finding_ids must be a list of strings")
    limit = body.get("limit", 10)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    return body, ids, limit


@bp.post("/scans/<sid>/ai/preview")
def preview(sid):
    store, scan, err = _load(sid)
    if err:
        return err
    try:
        _, ids, limit = _params()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    payload = gemini.build_payload(scan["result"], limit, ids)
    return jsonify(payload=payload, ai=gemini.status(), model=gemini.status()["model"],
                   disclosure="If you proceed, only the redacted finding snippets shown here (not the repository) are "
                              "sent to Google's Gemini API. Secrets are masked before transmission.")


@bp.post("/scans/<sid>/ai/review")
def review(sid):
    store, scan, err = _load(sid)
    if err:
        return err
    try:
        body, ids, limit = _params()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    result = scan["result"]
    out = gemini.run_review(result, consent=body.get("consent") is True, limit=limit, finding_ids=ids)
    out["requested_at"] = time.time()
    result["ai"]["gemini"] = out if out["mode"] == "gemini" else None
    result["ai"]["last_attempt"] = {"mode": out["mode"], "fallback_reason": out.get("fallback_reason"),
                                    "message": out.get("message"), "at": out["requested_at"]}
    store.save_result(sid, result)
    return jsonify(out)
