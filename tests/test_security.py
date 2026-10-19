def test_sql_injection_in_login_is_not_executed(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice' OR 1=1 --", "password": "anything"},
    )
    assert response.status_code == 401


def test_sql_injection_in_search_is_not_executed(client, auth_headers):
    response = client.get(
        "/api/data",
        headers=auth_headers,
        query_string={"q": "' OR 1=1 --"},
    )
    assert response.status_code == 200
    assert response.get_json()["count"] == 0


def test_xss_payload_is_escaped_on_output(client, auth_headers):
    payload_title = '<script>alert("xss")</script>'
    payload_body = '<img src=x onerror="alert(1)">'
    created = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": payload_title, "body": payload_body},
    )
    assert created.status_code == 201
    item = created.get_json()["item"]
    assert "<script>" not in item["title"]
    assert "&lt;script&gt;" in item["title"]
    assert "<img" not in item["body"]
    assert "&lt;img" in item["body"]
    assert '&quot;alert(1)&quot;' in item["body"]

    listing = client.get("/api/data", headers=auth_headers).get_json()
    assert all("<script>" not in post["title"] for post in listing["items"])


def test_response_has_security_headers(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
