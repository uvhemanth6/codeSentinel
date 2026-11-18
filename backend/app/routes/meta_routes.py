import shutil
import sys

from flask import Blueprint, current_app, jsonify

from ..ai import gemini
from ..analyzers.base import all_analyzers
from ..security.rules import RULES
from ..services.languages import all_languages
from ..services.runner import SAMPLES

bp = Blueprint("meta", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    try:
        import bandit  # noqa: F401
        bandit_ok = True
    except ImportError:
        bandit_ok = False
    return jsonify(
        status="ok", python=sys.version.split()[0],
        tools={"bandit": bandit_ok, "semgrep": bool(shutil.which("semgrep")), "gemini": gemini.status()},
        limits={"max_upload_mb": current_app.config["MAX_UPLOAD_MB"], "max_files": current_app.config["MAX_FILES"],
                "max_uncompressed_mb": current_app.config["MAX_UNCOMPRESSED_MB"]},
        engine={"analyzers": [{"name": a.name, "stage": a.stage} for a in all_analyzers()],
                "security_rules": len(RULES)},
        languages=[{"name": l.name, "support": l.support, "extensions": list(l.extensions)} for l in all_languages()],
        samples=[{"id": k, "label": v} for k, v in SAMPLES.items()])
