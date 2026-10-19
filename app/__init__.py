"""Application factory for the Lab 1 secure REST API.

Design goals (mapped to the lab requirements):
  * SQL injection  -> every SQL statement uses parameter binding (see app/db.py)
  * XSS            -> all string values leaving the API are HTML-escaped (app/security.py)
  * Broken auth    -> bcrypt password hashes + short-lived HS256 JWT + strict middleware
"""
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify

from .config import load_config
from .db import close_db, init_db
from .errors import register_error_handlers


def create_app(config: str | dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(load_config(config))

    logging.basicConfig(
        level=getattr(logging, app.config["LOG_LEVEL"], logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    # --- database lifecycle -------------------------------------------------
    os.makedirs(app.instance_path, exist_ok=True)
    if not app.config.get("DATABASE"):
        app.config["DATABASE"] = os.path.join(app.instance_path, "app.db")
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    # --- blueprints ---------------------------------------------------------
    from .api import api_bp
    from .auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    register_error_handlers(app)

    @app.get("/health")
    def health():
        return jsonify(status="ok", service="lab1-secure-api")

    # --- hardening headers on every response --------------------------------
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.setdefault("Cache-Control", "no-store")
        # Tokens must never be cached by an intermediary.
        return response

    return app


__all__ = ["create_app"]
