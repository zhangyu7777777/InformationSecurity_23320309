"""Application factory for the secure lab API."""

from __future__ import annotations

import os

from flask import Flask, jsonify

from . import db
from .routes import api


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        DATABASE=os.environ.get(
            "DATABASE", os.path.join(app.instance_path, "secure_api.sqlite3")
        ),
        JWT_SECRET=os.environ.get(
            "JWT_SECRET", "dev-only-change-this-secret-0123456789abcdef"
        ),
        JWT_ISSUER="hdu-secure-api",
        JWT_AUDIENCE="hdu-secure-api-client",
        JWT_EXPIRES_MINUTES=int(os.environ.get("JWT_EXPIRES_MINUTES", "30")),
        BCRYPT_ROUNDS=int(os.environ.get("BCRYPT_ROUNDS", "12")),
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    if test_config:
        app.config.update(test_config)

    if (
        not app.config["TESTING"]
        and app.config["JWT_SECRET"]
        == "dev-only-change-this-secret-0123456789abcdef"
    ):
        app.logger.warning(
            "JWT_SECRET is using the development default. Set it in .env before deploying."
        )

    db.init_app(app)
    app.register_blueprint(api)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        if response.is_json:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify(error="request body is too large"), 413

    @app.errorhandler(500)
    def internal_error(_error):
        # Do not leak exception details or stack traces to clients.
        return jsonify(error="internal server error"), 500

    with app.app_context():
        db.init_db()

    return app
