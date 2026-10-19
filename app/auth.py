"""Authentication blueprint: POST /auth/login."""
from __future__ import annotations

from functools import lru_cache

import bcrypt
from flask import Blueprint, current_app, jsonify

from .db import find_user_by_username
from .errors import AuthError
from .security import (
    client_key,
    create_access_token,
    login_limiter,
    parse_json_body,
    validate_password_field,
    validate_username,
    verify_password,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A throw-away hash used to keep the timing of "unknown user" and
    "wrong password" indistinguishable (defeats user enumeration by timing)."""
    return bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(4)).decode()


@auth_bp.post("/login")
def login():
    """Authenticate a user and return a short-lived JWT.

    Body: {"username": "...", "password": "..."}
    """
    data = parse_json_body()
    username = validate_username(data.get("username"))
    password = validate_password_field(data.get("password"))

    cfg = current_app.config
    key = client_key(username)
    login_limiter.check(key, cfg["LOGIN_MAX_ATTEMPTS"], cfg["LOGIN_WINDOW_SECONDS"])

    user = find_user_by_username(username)

    if user is None:
        # Burn the same amount of CPU as a real verification.
        verify_password(password, _dummy_hash())
        login_limiter.register_failure(key)
        raise AuthError("Invalid username or password.")

    if not verify_password(password, user["password_hash"]):
        login_limiter.register_failure(key)
        raise AuthError("Invalid username or password.")

    login_limiter.reset(key)

    token, expires_in = create_access_token(
        user_id=user["id"], username=user["username"], role=user["role"]
    )
    current_app.logger.info("User %s authenticated", user["username"])
    return jsonify(
        access_token=token,
        token_type="Bearer",
        expires_in=expires_in,
        user={"id": user["id"], "username": user["username"], "role": user["role"]},
    )
