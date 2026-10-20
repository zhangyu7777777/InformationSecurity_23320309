import html
import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

DB = os.environ.get("DATABASE", "lab.db")
SECRET = os.environ.get("JWT_SECRET", "this-is-a-simple-secret-key-123456")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            body TEXT
        )
        """
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("alice", hash_password("123456"), "admin"),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("bob", hash_password("123456"), "user"),
        )
        conn.execute(
            "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
            (1, "Hello", "This is my first post."),
        )
    conn.commit()
    conn.close()


def make_token(user):
    data = {
        "user_id": user["id"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(data, SECRET, algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        data = jwt.decode(auth[7:], SECRET, algorithms=["HS256"])
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (data["user_id"],)
        ).fetchone()
        conn.close()
        return user
    except Exception:
        return None


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "please login"}), 401
        return func(user, *args, **kwargs)

    return wrapper


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "bad request"}), 400

    username = data.get("login") or data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "wrong username or password"}), 401

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if user is None or not bcrypt.checkpw(
        password.encode(), user["password_hash"].encode()
    ):
        return jsonify({"error": "wrong username or password"}), 401

    return jsonify({"token": make_token(user)})


@app.route("/api/data", methods=["GET"])
@login_required
def get_data(user):
    q = request.args.get("q", "")
    conn = get_db()
    if q:
        rows = conn.execute(
            """
            SELECT posts.id, posts.title, posts.body, users.username
            FROM posts JOIN users ON users.id = posts.user_id
            WHERE posts.title LIKE ? OR posts.body LIKE ?
            ORDER BY posts.id DESC
            """,
            ("%" + q + "%", "%" + q + "%"),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT posts.id, posts.title, posts.body, users.username
            FROM posts JOIN users ON users.id = posts.user_id
            ORDER BY posts.id DESC
            """
        ).fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append(
            {
                "id": row["id"],
                "title": html.escape(row["title"]),
                "body": html.escape(row["body"]),
                "username": html.escape(row["username"]),
            }
        )
    return jsonify(result)


@app.route("/api/data", methods=["POST"])
@login_required
def add_data(user):
    data = request.get_json()
    if not data:
        return jsonify({"error": "bad request"}), 400

    title = str(data.get("title", "")).strip()
    body = str(data.get("body", "")).strip()
    if not title or not body:
        return jsonify({"error": "title and body are required"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
        (user["id"], title, body),
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "ok"})


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
