"""SQLite helpers. Every query uses bound parameters, never string concatenation."""

from __future__ import annotations

import sqlite3

import click
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'
                  CHECK (role IN ('user', 'admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()


def seed_demo_data() -> None:
    """Create demo accounts and posts if the database is empty."""
    from .security import hash_password

    conn = get_db()
    row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
    if row["count"]:
        return

    users = [
        ("alice", "AlicePass123!", "admin"),
        ("bob", "BobPass123!", "user"),
    ]
    for username, password, role in users:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )

    alice_id = conn.execute(
        "SELECT id FROM users WHERE username = ?", ("alice",)
    ).fetchone()["id"]
    posts = [
        (alice_id, "Welcome", "This is the first demo post."),
        (alice_id, "Security note", "Always validate and encode untrusted data."),
    ]
    conn.executemany(
        "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)", posts
    )
    conn.commit()


@click.command("init-db")
def init_db_command() -> None:
    """Create tables and demo data."""
    init_db()
    seed_demo_data()
    click.echo("Initialized the database.")


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
