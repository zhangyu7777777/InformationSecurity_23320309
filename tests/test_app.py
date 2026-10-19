import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, init_db  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    app.config.update(
        TESTING=True,
        DATABASE=str(tmp_path / "test.db"),
        JWT_SECRET="test-secret-0123456789abcdef0123456789",
    )
    with app.app_context():
        init_db()
    return app.test_client()


def get_token(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "AlicePass123!"},
    )
    return response.get_json()["access_token"]


def test_login(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "AlicePass123!"},
    )
    assert response.status_code == 200
    assert "access_token" in response.get_json()


def test_wrong_password(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "wrong"},
    )
    assert response.status_code == 401


def test_data_requires_token(client):
    assert client.get("/api/data").status_code == 401


def test_data_with_token(client):
    token = get_token(client)
    response = client.get(
        "/api/data", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 200
    assert response.get_json()["count"] == 1


def test_sql_injection(client):
    token = get_token(client)
    response = client.get(
        "/api/data?q=' OR 1=1 --",
        headers={"Authorization": "Bearer " + token},
    )
    assert response.get_json()["count"] == 0


def test_xss_is_escaped(client):
    token = get_token(client)
    response = client.post(
        "/api/data",
        headers={"Authorization": "Bearer " + token},
        json={"title": "<script>alert(1)</script>", "body": "test"},
    )
    assert "&lt;script&gt;" in response.get_json()["title"]
