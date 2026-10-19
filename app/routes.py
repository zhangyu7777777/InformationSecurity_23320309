"""API endpoints."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db
from .security import (
    clean_text,
    create_access_token,
    escape_for_output,
    require_auth,
    validate_password,
    validate_username,
    verify_password,
)

api = Blueprint("api", __name__)

# Small in-process brute-force guard. A production deployment should use Redis.
_attempts: dict[str, deque[float]] = defaultdict(deque)
_attempts_lock = threading.Lock()
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW_SECONDS = 300


def _rate_limited(key: str) -> bool:
    now = time.monotonic()
    with _attempts_lock:
        bucket = _attempts[key]
        while bucket and now - bucket[0] > ATTEMPT_WINDOW_SECONDS:
            bucket.popleft()
        return len(bucket) >= MAX_ATTEMPTS


def _record_failure(key: str) -> None:
    with _attempts_lock:
        _attempts[key].append(time.monotonic())


def _clear_failures(key: str) -> None:
    with _attempts_lock:
        _attempts.pop(key, None)


def _json_body() -> dict | None:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _serialize_post(row) -> dict:
    return {
        "id": row["id"],
        "title": escape_for_output(row["title"]),
        "body": escape_for_output(row["body"]),
        "author": escape_for_output(row["username"]),
        "created_at": row["created_at"],
    }


@api.get("/health")
def health():
    return jsonify(status="ok")


@api.post("/auth/login")
def login():
    body = _json_body()
    if body is None:
        return jsonify(error="JSON body required"), 400

    login_value = body.get("login", body.get("username"))
    password = body.get("password")
    try:
        username = validate_username(login_value)
    except ValueError:
        return jsonify(error="invalid credentials"), 401
    if not isinstance(password, str) or not password:
        return jsonify(error="invalid credentials"), 401

    key = f"{request.remote_addr}|{username.lower()}"
    if _rate_limited(key):
        return jsonify(error="too many login attempts, try again later"), 429

    user = get_db().execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if user is None or not verify_password(password, user["password_hash"]):
        _record_failure(key)
        # Same response for unknown users and wrong passwords: no user enumeration.
        return jsonify(error="invalid credentials"), 401

    _clear_failures(key)
    token, expires_in = create_access_token(user)
    return jsonify(
        access_token=token,
        # This is the OAuth token type, not a secret.
        token_type="Bearer",  # nosec B106
        expires_in=expires_in,
    )


@api.get("/api/me")
@require_auth
def me():
    user = g.current_user
    return jsonify(
        id=user["id"],
        username=escape_for_output(user["username"]),
        role=user["role"],
    )


@api.get("/api/data")
@require_auth
def list_data():
    query = request.args.get("q", "", type=str).strip()
    if len(query) > 100:
        return jsonify(error="q must be at most 100 characters"), 400

    conn = get_db()
    if query:
        # Bound parameter: the value can never change the SQL statement.
        rows = conn.execute(
            """
            SELECT posts.id, posts.title, posts.body, posts.created_at,
                   users.username
            FROM posts JOIN users ON users.id = posts.author_id
            WHERE posts.title LIKE ? OR posts.body LIKE ?
            ORDER BY posts.id DESC
            """,
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT posts.id, posts.title, posts.body, posts.created_at,
                   users.username
            FROM posts JOIN users ON users.id = posts.author_id
            ORDER BY posts.id DESC
            """
        ).fetchall()
    return jsonify(items=[_serialize_post(row) for row in rows], count=len(rows))


@api.post("/api/data")
@require_auth
def create_data():
    body = _json_body()
    if body is None:
        return jsonify(error="JSON body required"), 400
    try:
        title = clean_text(body.get("title"), field="title", max_length=100)
        content = clean_text(body.get("body"), field="body", max_length=2000)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
        (g.current_user["id"], title, content),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT posts.id, posts.title, posts.body, posts.created_at, users.username
        FROM posts JOIN users ON users.id = posts.author_id
        WHERE posts.id = ?
        """,
        (cursor.lastrowid,),
    ).fetchone()
    return jsonify(item=_serialize_post(row)), 201


@api.delete("/api/data/<int:post_id>")
@require_auth
def delete_data(post_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT author_id FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if row["author_id"] != g.current_user["id"] and g.current_user["role"] != "admin":
        return jsonify(error="forbidden"), 403

    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    return "", 204
