"""Authentication tests: login, JWT verification, brute-force protection."""
from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from app.db import get_db
from tests.conftest import ALICE


def test_login_success_returns_bearer_token(client, login):
    resp = login()
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 15 * 60
    assert body["access_token"].count(".") == 2  # header.payload.signature
    assert body["user"] == {"id": 1, "username": "alice", "role": "admin"}


def test_login_wrong_password_is_rejected(client, login):
    resp = login({"username": "alice", "password": "WrongPassword1!"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["message"] == "Invalid username or password."


def test_login_unknown_user_is_indistinguishable(client, login):
    wrong_pw = login({"username": "alice", "password": "nope"}).get_json()
    unknown = login({"username": "ghost", "password": "nope"}).get_json()
    # Same status and same body: no user enumeration.
    assert wrong_pw == unknown


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": "alice"},
        {"password": "Passw0rd!Alice"},
        {"username": 123, "password": "x"},
        {"username": "alice", "password": None},
        {"username": "a" * 300, "password": "x"},
    ],
)
def test_login_malformed_payload(client, payload):
    resp = client.post("/auth/login", json=payload)
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_login_rejects_non_json_body(client):
    resp = client.post("/auth/login", data="username=alice&password=x",
                       content_type="application/x-www-form-urlencoded")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "bad_request"


def test_passwords_are_bcrypt_hashed_not_plaintext(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()
    digest = row["password_hash"]
    assert digest.startswith("$2b$")
    assert "Passw0rd!Alice" not in digest
    # 4 = rounds used in tests; production default is 12.
    rounds = int(digest.split("$")[2])
    assert rounds == 4


def test_timing_dummy_hash_matches_the_configured_cost(app):
    """The decoy verification for unknown users must cost as much as a real one,
    otherwise the "unknown user" path answers measurably faster."""
    from app.auth import _dummy_hash

    with app.app_context():
        digest = _dummy_hash(app.config["BCRYPT_ROUNDS"])
    assert digest.startswith("$2b$")
    assert int(digest.split("$")[2]) == app.config["BCRYPT_ROUNDS"]


def test_protected_endpoint_without_token(client):
    resp = client.get("/api/data")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == 'Bearer error="missing_token"'


def test_protected_endpoint_with_garbage_token(client):
    resp = client.get("/api/data", headers={"Authorization": "Bearer not.a.token"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["message"] == "Invalid token."


def test_protected_endpoint_with_wrong_scheme(client, token):
    resp = client.get("/api/data", headers={"Authorization": f"Basic {token}"})
    assert resp.status_code == 401


def test_expired_token_is_rejected(client, app):
    now = int(time.time())
    expired = pyjwt.encode(
        {
            "sub": "1",
            "username": "alice",
            "role": "admin",
            "iss": app.config["JWT_ISSUER"],
            "aud": app.config["JWT_AUDIENCE"],
            "iat": now - 7200,
            "nbf": now - 7200,
            "exp": now - 3600,
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401
    assert "expired" in resp.get_json()["error"]["message"].lower()


def test_token_signed_with_attacker_key_is_rejected(client, app):
    forged = pyjwt.encode(
        {
            "sub": "1",
            "username": "alice",
            "role": "admin",
            "iss": app.config["JWT_ISSUER"],
            "aud": app.config["JWT_AUDIENCE"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        # a wrong key of realistic length, so the failure is about the key
        # value and not about PyJWT's short-key warning
        "attacker-controlled-secret-0123456789",
        algorithm="HS256",
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_alg_none_token_is_rejected(client, app):
    unsigned = pyjwt.encode(
        {"sub": "1", "iss": app.config["JWT_ISSUER"],
         "aud": app.config["JWT_AUDIENCE"], "exp": int(time.time()) + 3600},
        key=None,
        algorithm="none",
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {unsigned}"})
    assert resp.status_code == 401


def test_token_for_deleted_user_is_rejected(client, app, token):
    with app.app_context():
        conn = get_db()
        conn.execute("DELETE FROM users WHERE username = ?", ("alice",))
        conn.commit()
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["message"] == "Account no longer exists."


def test_login_is_rate_limited(client, login):
    payload = {"username": "bob", "password": "wrong-password"}
    for _ in range(5):
        assert login(payload).status_code == 401
    blocked = login(payload)
    assert blocked.status_code == 429
    assert blocked.get_json()["error"]["code"] == "too_many_requests"
    assert "Retry-After" in blocked.headers
    # A different account is not affected by bob's failures.
    assert login(ALICE).status_code == 200
