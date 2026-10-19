"""Attack-oriented regression tests: SQL injection and XSS must stay inert.

These are the tests the report points at as *evidence* that the two required
protection mechanisms actually work.
"""
from __future__ import annotations

import pytest

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "alice' --",
    "' OR 1=1 --",
    "admin'/*",
    "'; DROP TABLE users; --",
    "\" OR \"\"=\"",
    "alice' UNION SELECT 1,2,3,4,5 --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "\"><svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<iframe src=javascript:alert(1)>",
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_in_login_never_authenticates(client, payload):
    resp = client.post("/auth/login", json={"username": payload, "password": payload})
    assert resp.status_code in (401, 429)
    assert "access_token" not in resp.get_json()


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_tautology_password_does_not_bypass(client, payload):
    resp = client.post("/auth/login", json={"username": "alice", "password": payload})
    assert resp.status_code == 401
    assert "access_token" not in resp.get_json()


def test_sqli_in_search_is_treated_as_literal_text(client, auth):
    resp = client.get("/api/data", headers=auth, query_string={"q": "' OR 1=1 --"})
    assert resp.status_code == 200
    body = resp.get_json()
    # The payload is matched literally, so nothing is returned and the table
    # is intact.
    assert body["total"] == 0
    assert body["data"] == []


def test_sqli_drop_table_payload_leaves_schema_intact(client, auth):
    client.get("/api/data", headers=auth, query_string={"q": "'; DROP TABLE posts; --"})
    resp = client.get("/api/data", headers=auth)
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 2


def test_sqli_error_messages_are_not_leaked(client, auth):
    resp = client.get("/api/data", headers=auth, query_string={"q": "%' AND 1=CAST((SELECT 1) AS int)--"})
    assert resp.status_code in (200, 400)
    text = resp.get_data(as_text=True).lower()
    for leak in ("sqlite", "syntax error", "sql", "traceback", "select "):
        assert leak not in text


def test_stored_xss_is_escaped_on_output(client, auth):
    payload = "<script>alert('XSS')</script>"
    created = client.post(
        "/api/posts", headers=auth, json={"title": "xss demo", "body": payload}
    )
    assert created.status_code == 201
    # The write response is already encoded...
    assert "<script>" not in created.get_data(as_text=True)

    # ...and so is every subsequent read.
    feed = client.get("/api/data", headers=auth)
    text = feed.get_data(as_text=True)
    assert payload not in text
    assert "&lt;script&gt;" in text
    assert "<script>" not in text


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_reflected_xss_is_escaped(client, auth, payload):
    created = client.post(
        "/api/posts", headers=auth, json={"title": payload, "body": payload}
    )
    assert created.status_code == 201
    for response_text in (created.get_data(as_text=True),
                          client.get("/api/data", headers=auth).get_data(as_text=True)):
        assert "<script" not in response_text.lower()
        assert "<img" not in response_text.lower()
        assert "<svg" not in response_text.lower()
        assert "<iframe" not in response_text.lower()


def test_escaping_keeps_legitimate_unicode(client, auth):
    created = client.post(
        "/api/posts", headers=auth, json={"title": "Привет 你好", "body": "emoji ✅ & <ok>"}
    )
    assert created.status_code == 201
    body = created.get_json()["post"]
    assert body["title"] == "Привет 你好"
    assert body["body"] == "emoji ✅ &amp; &lt;ok&gt;"
