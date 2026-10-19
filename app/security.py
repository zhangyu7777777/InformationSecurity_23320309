"""Password hashing, JWT handling, validation, and output encoding."""

from __future__ import annotations

import html
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password must be at most 72 bytes")
    rounds = current_app.config["BCRYPT_ROUNDS"]
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds)).decode(
        "ascii"
    )


def verify_password(password: str, password_hash: str) -> bool:
    if not isinstance(password, str) or not password:
        return False
    if len(password.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def create_access_token(user) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires_in = int(current_app.config["JWT_EXPIRES_MINUTES"]) * 60
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(
        payload, current_app.config["JWT_SECRET"], algorithm="HS256"
    )
    return token, expires_in


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=["HS256"],
        issuer=current_app.config["JWT_ISSUER"],
        audience=current_app.config["JWT_AUDIENCE"],
        options={"require": ["sub", "iat", "exp", "iss", "aud"]},
    )


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_auth(view):
    """Reject missing, malformed, expired, or forged JWTs."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _bearer_token()
        if token is None:
            return jsonify(error="authentication required"), 401
        try:
            payload = decode_access_token(token)
            user_id = int(payload["sub"])
        except (jwt.InvalidTokenError, ValueError, TypeError):
            return jsonify(error="invalid or expired token"), 401

        from .db import get_db

        user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            return jsonify(error="invalid or expired token"), 401

        g.current_user = user
        g.jwt_payload = payload
        return view(*args, **kwargs)

    return wrapped


def clean_text(value: object, *, field: str, max_length: int) -> str:
    """Validate text before it is stored; output encoding happens on read."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value:
        raise ValueError(f"{field} is required")
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    if CONTROL_CHARS_RE.search(value):
        raise ValueError(f"{field} contains control characters")
    return value


def validate_username(value: object) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        raise ValueError("username must be 3-32 letters, digits, dot, dash, or underscore")
    return value


def validate_password(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("password must be a string")
    if not 8 <= len(value) <= 72:
        raise ValueError("password must be 8-72 characters")
    return value


def escape_for_output(value: str) -> str:
    """Escape HTML metacharacters so the value is safe in an HTML context."""
    return html.escape(value, quote=True)
