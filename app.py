import html
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("DATABASE", "app.db")
app.config["JWT_SECRET"] = os.environ.get(
    "JWT_SECRET", "dev-secret-change-me-0123456789abcdef"
)
app.config["JWT_EXPIRES_MINUTES"] = 30


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("alice", hash_password("AlicePass123!"), "admin"),
        )
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("bob", hash_password("BobPass123!"), "user"),
        )
        db.execute(
            "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
            (1, "Welcome", "This is a demo post."),
        )
    db.commit()


def create_token(user):
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=app.config["JWT_EXPIRES_MINUTES"]),
    }
    return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="missing token"), 401

        token = header[7:]
        try:
            data = jwt.decode(
                token, app.config["JWT_SECRET"], algorithms=["HS256"]
            )
            user_id = int(data["sub"])
        except (jwt.InvalidTokenError, KeyError, ValueError):
            return jsonify(error="invalid token"), 401

        user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            return jsonify(error="invalid token"), 401

        g.user = user
        return view(*args, **kwargs)

    return wrapper


def clean_text(value, max_length):
    if not isinstance(value, str):
        raise ValueError
    value = value.strip()
    if not value or len(value) > max_length:
        raise ValueError
    return value


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("login") or data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="invalid credentials"), 401

    user = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None or not check_password(password, user["password_hash"]):
        return jsonify(error="invalid credentials"), 401

    token_type = "Bearer"  # nosec B105
    return jsonify(access_token=create_token(user), token_type=token_type)


@app.get("/api/data")
@login_required
def get_data():
    query = request.args.get("q", "").strip()
    db = get_db()
    sql = """
        SELECT posts.id, posts.title, posts.body, users.username
        FROM posts JOIN users ON users.id = posts.user_id
    """
    if query:
        rows = db.execute(
            sql + " WHERE posts.title LIKE ? OR posts.body LIKE ? ORDER BY posts.id DESC",
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
    else:
        rows = db.execute(sql + " ORDER BY posts.id DESC").fetchall()

    items = [
        {
            "id": row["id"],
            "title": html.escape(row["title"]),
            "body": html.escape(row["body"]),
            "author": html.escape(row["username"]),
        }
        for row in rows
    ]
    return jsonify(count=len(items), items=items)


@app.post("/api/data")
@login_required
def add_data():
    data = request.get_json(silent=True) or {}
    try:
        title = clean_text(data.get("title"), 100)
        body = clean_text(data.get("body"), 2000)
    except ValueError:
        return jsonify(error="title and body are required"), 400

    db = get_db()
    cursor = db.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
        (g.user["id"], title, body),
    )
    db.commit()
    return jsonify(
        id=cursor.lastrowid,
        title=html.escape(title),
        body=html.escape(body),
    ), 201


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec B104
