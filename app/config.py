"""Environment-driven configuration.

Secrets are never hardcoded: they come from the environment (or a local .env
loaded by the developer).  In ``production`` mode a missing SECRET_KEY is a
fatal error -- we refuse to boot with a predictable signing key.
"""
from __future__ import annotations

import os
import secrets


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_config(name: str | dict | None = None) -> dict:
    if isinstance(name, dict):
        base = _base_config()
        base.update(name)
        return base

    env = (name or os.environ.get("APP_ENV") or "development").lower()
    cfg = _base_config()
    cfg["ENV_NAME"] = env

    if env in ("production", "prod"):
        secret = os.environ.get("SECRET_KEY", "").strip()
        if not secret:
            raise RuntimeError(
                "SECRET_KEY is not set. Refusing to start in production with an "
                "auto-generated signing key."
            )
        cfg["SECRET_KEY"] = secret
        cfg["DEBUG"] = False
        cfg["TESTING"] = False
    elif env in ("testing", "test"):
        cfg["SECRET_KEY"] = os.environ.get("SECRET_KEY", "testing-key-not-for-production")
        cfg["DEBUG"] = False
        cfg["TESTING"] = True
        cfg["BCRYPT_ROUNDS"] = 4  # keep the test-suite fast
    else:
        # Development: generate an ephemeral key so nothing is committed to git.
        cfg["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        cfg["DEBUG"] = True
        cfg["TESTING"] = False

    if os.environ.get("DATABASE_PATH"):
        cfg["DATABASE"] = os.environ["DATABASE_PATH"]

    return cfg


def _base_config() -> dict:
    return {
        "ENV_NAME": "development",
        "SECRET_KEY": secrets.token_hex(32),
        # Resolved to <app.instance_path>/app.db by create_app() when unset.
        "DATABASE": os.environ.get("DATABASE_PATH"),
        # --- JWT ---
        "JWT_ALGORITHM": "HS256",
        "JWT_ISSUER": "lab1-secure-api",
        "JWT_AUDIENCE": "lab1-clients",
        "JWT_TTL_MINUTES": _env_int("JWT_TTL_MINUTES", 15),
        "JWT_LEEWAY_SECONDS": 5,
        # --- password hashing ---
        "BCRYPT_ROUNDS": _env_int("BCRYPT_ROUNDS", 12),
        # bcrypt only consumes the first 72 bytes; longer input is rejected
        # up-front instead of being silently truncated.
        "PASSWORD_MAX_BYTES": 72,
        "PASSWORD_MIN_LENGTH": 8,
        # --- abuse protection ---
        "LOGIN_MAX_ATTEMPTS": _env_int("LOGIN_MAX_ATTEMPTS", 5),
        "LOGIN_WINDOW_SECONDS": _env_int("LOGIN_WINDOW_SECONDS", 300),
        # --- request limits ---
        "MAX_CONTENT_LENGTH": 64 * 1024,
        "MAX_TEXT_LENGTH": 2000,
        "LOG_LEVEL": os.environ.get("LOG_LEVEL", "INFO"),
    }
