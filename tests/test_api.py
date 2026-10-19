"""Functional tests for the protected data endpoints."""
from __future__ import annotations

import pytest


def test_data_requires_authentication(client):
    assert client.get("/api/data").status_code == 401


def test_data_returns_seeded_posts(client, auth):
    resp = client.get("/api/data", headers=auth)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 2
    assert len(body["data"]) == 2
    assert {"id", "title", "body", "author", "created_at"} <= set(body["data"][0])


def test_data_pagination(client, auth):
    first = client.get("/api/data?limit=1&offset=0", headers=auth).get_json()
    second = client.get("/api/data?limit=1&offset=1", headers=auth).get_json()
    assert first["total"] == 2
    assert len(first["data"]) == 1 and len(second["data"]) == 1
    assert first["data"][0]["id"] != second["data"][0]["id"]


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=abc", "offset=-1"])
def test_data_rejects_invalid_pagination(client, auth, query):
    resp = client.get(f"/api/data?{query}", headers=auth)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "validation_error"


def test_create_post_and_read_it_back(client, auth):
    created = client.post(
        "/api/posts",
        headers=auth,
        json={"title": "My first post", "body": "Hello from pytest."},
    )
    assert created.status_code == 201
    post = created.get_json()["post"]
    assert post["author"] == "alice"

    feed = client.get("/api/data", headers=auth).get_json()
    assert feed["total"] == 3
    assert any(item["id"] == post["id"] for item in feed["data"])


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": "ab", "body": "too short title"},
        {"title": "x" * 121, "body": "title too long"},
        {"title": "ok title"},
        {"title": "ok title", "body": ""},
        {"title": "ok title", "body": 42},
        {"title": "bad\x00title", "body": "control char"},
    ],
)
def test_create_post_validation(client, auth, payload):
    resp = client.post("/api/posts", headers=auth, json=payload)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "validation_error"


def test_me_endpoint(client, auth):
    resp = client.get("/api/me", headers=auth)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["role"] == "admin"
    assert body["token_expires_at"] > 0


def test_unknown_route_returns_json(client):
    resp = client.get("/api/nope")
    assert resp.status_code == 404
    assert resp.is_json
    assert resp.get_json()["error"]["code"] == "not_found"


def test_wrong_method_returns_json(client):
    resp = client.get("/auth/login")
    assert resp.status_code == 405
    assert resp.is_json


def test_security_headers_present(client, auth):
    resp = client.get("/api/data", headers=auth)
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store"


def test_oversized_body_is_rejected(client, auth):
    big = {"title": "big", "body": "A" * (70 * 1024)}
    resp = client.post("/api/posts", headers=auth, json=big)
    assert resp.status_code == 413


def test_title_rejects_newlines_while_body_allows_them(client, auth):
    """Single-line and multi-line fields must not be validated identically."""
    bad = client.post(
        "/api/posts", headers=auth,
        json={"title": "line one\nline two", "body": "fine"},
    )
    assert bad.status_code == 400
    assert "title" in bad.get_json()["error"]["message"]

    bad_crlf = client.post(
        "/api/posts", headers=auth,
        json={"title": "line one\r\nline two", "body": "fine"},
    )
    assert bad_crlf.status_code == 400

    good = client.post(
        "/api/posts", headers=auth,
        json={"title": "single line", "body": "line one\nline two"},
    )
    assert good.status_code == 201


def test_error_responses_carry_security_headers(client):
    """Hardening headers must survive the error path, not only 2xx responses."""
    resp = client.get("/api/data")  # 401
    assert resp.status_code == 401
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_health_and_login_are_public(client):
    assert client.get("/health").status_code == 200
    assert client.post("/auth/login", json={}).status_code == 401  # reachable, rejected
