import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402
from app.db import get_db  # noqa: E402
from app.security import hash_password  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "JWT_SECRET": "test-secret-that-is-at-least-32-bytes-long",
            "BCRYPT_ROUNDS": 4,
        }
    )
    with application.app_context():
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("alice", hash_password("AlicePass123!"), "admin"),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("bob", hash_password("BobPass123!"), "user"),
        )
        alice_id = conn.execute(
            "SELECT id FROM users WHERE username = 'alice'"
        ).fetchone()["id"]
        conn.execute(
            "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
            (alice_id, "Welcome", "First post"),
        )
        conn.commit()
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def alice_token(client):
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AlicePass123!"},
    )
    assert response.status_code == 200
    return response.get_json()["access_token"]


@pytest.fixture()
def auth_headers(alice_token):
    return {"Authorization": f"Bearer {alice_token}"}
