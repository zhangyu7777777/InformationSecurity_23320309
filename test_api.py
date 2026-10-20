import os

os.environ["DATABASE"] = "test.db"
if os.path.exists("test.db"):
    os.remove("test.db")

from app import app

client = app.test_client()


def login():
    res = client.post(
        "/auth/login",
        json={"login": "alice", "password": "123456"},
    )
    return res.get_json()["token"]


def test_login():
    res = client.post(
        "/auth/login",
        json={"login": "alice", "password": "123456"},
    )
    assert res.status_code == 200


def test_wrong_password():
    res = client.post(
        "/auth/login",
        json={"login": "alice", "password": "wrong"},
    )
    assert res.status_code == 401


def test_no_token():
    res = client.get("/api/data")
    assert res.status_code == 401


def test_get_data():
    token = login()
    res = client.get(
        "/api/data",
        headers={"Authorization": "Bearer " + token},
    )
    assert res.status_code == 200
    assert len(res.get_json()) > 0


def test_sql_injection():
    token = login()
    res = client.get(
        "/api/data?q=' OR 1=1 --",
        headers={"Authorization": "Bearer " + token},
    )
    assert res.get_json() == []


def test_xss():
    token = login()
    res = client.post(
        "/api/data",
        headers={"Authorization": "Bearer " + token},
        json={"title": "<script>alert(1)</script>", "body": "test"},
    )
    assert res.status_code == 200

    res = client.get(
        "/api/data",
        headers={"Authorization": "Bearer " + token},
    )
    text = str(res.get_json())
    assert "<script>" not in text
