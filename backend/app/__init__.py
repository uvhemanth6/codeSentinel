"""CodeSentinel backend application factory."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS

from .config import Config
from .services.store import Store


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    data_dir = Path(app.config["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    Config.DATA_DIR = data_dir  # runner uses it for temp dirs
    app.config["MAX_CONTENT_LENGTH"] = int(app.config["MAX_UPLOAD_MB"]) * 1024 * 1024 + 4096
    store = Store(app.config.get("DB_PATH") or data_dir / "codesentinel.db")
    store.fail_interrupted()
    app.extensions["store"] = store
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})
    logging.basicConfig(level=logging.INFO)

    from .routes import ai_routes, meta_routes, scan_routes, settings_routes
    for bp in (meta_routes.bp, scan_routes.bp, ai_routes.bp, settings_routes.bp):
        app.register_blueprint(bp)

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error=f"Upload exceeds the {app.config['MAX_UPLOAD_MB']} MB limit"), 413

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="Not found"), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify(error="Internal server error"), 500

    # Serve the built frontend when present (single-process deployment).
    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist.exists():
        from flask import send_from_directory

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def spa(path):
            if path.startswith("api/"):
                return jsonify(error="Not found"), 404
            target = dist / path
            if path and target.is_file() and dist in target.resolve().parents:
                return send_from_directory(dist, path)
            return send_from_directory(dist, "index.html")
    return app
