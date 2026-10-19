"""Configuration tests: the app must fail closed in production.

A secure default is worth nothing if a missing variable silently degrades to a
predictable signing key, so these are treated as security tests rather than
housekeeping.
"""
from __future__ import annotations

import pytest

from app import create_app
from app.config import load_config


def test_production_without_secret_key_refuses_to_boot(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_config("production")


def test_production_accepts_an_explicit_secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 48)
    cfg = load_config("production")
    assert cfg["SECRET_KEY"] == "s" * 48
    assert cfg["DEBUG"] is False
    assert cfg["TESTING"] is False


def test_production_rejects_a_short_signing_key(monkeypatch):
    """HS256 with a key shorter than the 32-byte hash output weakens the MAC
    (RFC 7518 §3.2), so a short key must not be accepted in production."""
    monkeypatch.setenv("SECRET_KEY", "too-short")
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        load_config("production")


def test_development_never_reuses_a_signing_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    first = load_config("development")["SECRET_KEY"]
    second = load_config("development")["SECRET_KEY"]
    # An ephemeral key per process: nothing predictable is ever committed.
    assert first != second
    assert len(first) >= 32


def test_unknown_app_env_falls_back_to_development(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    cfg = load_config("staging-typo")
    assert cfg["DEBUG"] is True


def test_bcrypt_rounds_are_reduced_only_in_testing(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert load_config("testing")["BCRYPT_ROUNDS"] < load_config("development")["BCRYPT_ROUNDS"]


def test_dict_config_is_merged_over_defaults():
    cfg = load_config({"ENV_NAME": "custom", "JWT_TTL_MINUTES": 1})
    assert cfg["JWT_TTL_MINUTES"] == 1
    assert cfg["JWT_ALGORITHM"] == "HS256"  # default survived


def test_app_boots_with_explicit_config(db_path):
    app = create_app({"DATABASE": str(db_path), "SECRET_KEY": "k" * 32,
                      "BCRYPT_ROUNDS": 4, "TESTING": True})
    assert app.config["DATABASE"] == str(db_path)
    assert app.test_client().get("/health").status_code == 200
