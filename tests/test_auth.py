def test_login_returns_jwt(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "AlicePass123!"},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2


def test_login_rejects_wrong_password(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_login_rejects_unknown_user_with_same_message(client):
    response = client.post(
        "/auth/login",
        json={"login": "nobody", "password": "Whatever123!"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_protected_endpoint_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401


def test_protected_endpoint_rejects_forged_token(client):
    response = client.get(
        "/api/data", headers={"Authorization": "Bearer not.a.real.token"}
    )
    assert response.status_code == 401


def test_me_returns_current_user(client, auth_headers):
    response = client.get("/api/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.get_json()["username"] == "alice"
    assert response.get_json()["role"] == "admin"
