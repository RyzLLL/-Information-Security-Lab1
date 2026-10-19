"""Shared pytest fixtures.

Each test gets an isolated SQLite file so the suite never touches the
developer's ``instance/app.db``.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app import create_app

ALICE = {"username": "alice", "password": "Passw0rd!Alice"}
BOB = {"username": "bob", "password": "Passw0rd!Bob"}

# Project-local scratch area (also listed in .gitignore).
TEMP_ROOT = Path(__file__).resolve().parent.parent / ".pytest-tmp"


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The limiter is process-global; clear it so tests stay independent."""
    from app.security import login_limiter

    login_limiter._hits.clear()
    yield
    login_limiter._hits.clear()


@pytest.fixture
def db_path():
    """A throw-away SQLite path.

    Deliberately *not* pytest's ``tmp_path``: directories created with mode
    0o700 (which is what ``TemporaryDirectory`` does) lose the inherited access
    grants under some Windows configurations, and the sandbox used for this
    lab cannot even list them. A plain directory under the project works
    everywhere and is listed in .gitignore.
    """
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = TEMP_ROOT / f"test-{uuid.uuid4().hex}.db"
    yield path
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


@pytest.fixture
def app(db_path):
    cfg = {
        "TESTING": True,
        "DEBUG": False,
        "SECRET_KEY": "unit-test-secret-key",
        "DATABASE": str(db_path),
        "BCRYPT_ROUNDS": 4,          # keep the suite fast
        "JWT_TTL_MINUTES": 15,
        "JWT_LEEWAY_SECONDS": 0,
        "LOGIN_MAX_ATTEMPTS": 5,
        "LOGIN_WINDOW_SECONDS": 300,
    }
    return create_app(cfg)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(client):
    """Return a helper that logs in and returns the raw Flask response."""

    def _login(credentials: dict | None = None):
        return client.post("/auth/login", json=credentials or ALICE)

    return _login


@pytest.fixture
def token(client):
    resp = client.post("/auth/login", json=ALICE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["access_token"]


@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}
