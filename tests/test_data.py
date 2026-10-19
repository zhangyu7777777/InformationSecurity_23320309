def test_list_data_requires_auth(client):
    assert client.get("/api/data").status_code == 401


def test_list_data_with_token(client, auth_headers):
    response = client.get("/api/data", headers=auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    assert body["items"][0]["title"] == "Welcome"


def test_create_data(client, auth_headers):
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "New post", "body": "Hello world"},
    )
    assert response.status_code == 201
    assert response.get_json()["item"]["title"] == "New post"

    listing = client.get("/api/data", headers=auth_headers).get_json()
    assert listing["count"] == 2


def test_create_data_rejects_empty_fields(client, auth_headers):
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "  ", "body": "x"},
    )
    assert response.status_code == 400


def test_delete_requires_owner_or_admin(client, auth_headers):
    created = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "Temp", "body": "To delete"},
    ).get_json()["item"]
    response = client.delete(f"/api/data/{created['id']}", headers=auth_headers)
    assert response.status_code == 204


def test_delete_forbidden_for_other_user(client, auth_headers):
    created = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "Alice post", "body": "Private"},
    ).get_json()["item"]
    bob_token = client.post(
        "/auth/login", json={"login": "bob", "password": "BobPass123!"}
    ).get_json()["access_token"]
    response = client.delete(
        f"/api/data/{created['id']}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert response.status_code == 403
