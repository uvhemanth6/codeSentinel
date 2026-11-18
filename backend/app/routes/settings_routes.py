from flask import Blueprint, current_app, jsonify, request

from ..ai import gemini
from ..config import DEFAULT_SETTINGS, merged_settings

bp = Blueprint("settings", __name__, url_prefix="/api")


def _validate(payload: dict) -> dict:
    clean: dict = {}
    for section in ("weights", "severity_points", "confidence_factor", "norms", "thresholds"):
        vals = payload.get(section)
        if vals is None:
            continue
        if not isinstance(vals, dict):
            raise ValueError(f"{section} must be an object")
        clean[section] = {}
        for k, v in vals.items():
            if k not in DEFAULT_SETTINGS[section]:
                continue
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not (0 <= v <= 1000):
                raise ValueError(f"{section}.{k} must be a number between 0 and 1000")
            clean[section][k] = v
    if "size_factor" in payload:
        v = payload["size_factor"]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not (0 <= v <= 10):
            raise ValueError("size_factor must be between 0 and 10")
        clean["size_factor"] = v
    w = {**DEFAULT_SETTINGS["weights"], **clean.get("weights", {})}
    if sum(w.values()) <= 0:
        raise ValueError("At least one weight must be greater than zero")
    if any(v <= 0 for v in {**DEFAULT_SETTINGS["norms"], **clean.get("norms", {})}.values()):
        raise ValueError("norms must be greater than zero")
    return clean


@bp.get("/settings")
def get_settings():
    store = current_app.extensions["store"]
    return jsonify(settings=merged_settings(store.get_settings_overrides()), defaults=DEFAULT_SETTINGS,
                   ai=gemini.status())


@bp.put("/settings")
def put_settings():
    store = current_app.extensions["store"]
    try:
        clean = _validate(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    current = store.get_settings_overrides()
    for k, v in clean.items():
        current[k] = {**current.get(k, {}), **v} if isinstance(v, dict) else v
    store.set_settings_overrides(current)
    return jsonify(settings=merged_settings(current))


@bp.post("/settings/reset")
def reset_settings():
    current_app.extensions["store"].set_settings_overrides({})
    return jsonify(settings=merged_settings({}))
