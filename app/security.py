"""Security primitives: password hashing, JWT issuing/verification,
input validation, output escaping and a login rate limiter.

Nothing in this module trusts client input.
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, request
from markupsafe import escape

from .errors import ApiError, AuthError, RateLimitError, ValidationError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    """bcrypt with a per-password random salt and a configurable cost factor.

    Unlike SHA-256, bcrypt is deliberately slow and memory-hard-ish, so an
    offline brute-force attack against a stolen database is expensive.
    """
    rounds = current_app.config.get("BCRYPT_ROUNDS", 12)
    pw = plaintext.encode("utf-8")
    if len(pw) > current_app.config.get("PASSWORD_MAX_BYTES", 72):
        raise ValidationError("Password is too long.")
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds)).decode("utf-8")


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """Constant-time comparison performed by bcrypt itself."""
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(user_id: int, username: str, role: str) -> tuple[str, int]:
    """Issue a short-lived HS256 token. Returns (token, expires_in_seconds)."""
    cfg = current_app.config
    ttl = int(cfg["JWT_TTL_MINUTES"])
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iss": cfg["JWT_ISSUER"],
        "aud": cfg["JWT_AUDIENCE"],
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=ttl),
        "jti": secrets.token_hex(8),
    }
    token = jwt.encode(payload, cfg["SECRET_KEY"], algorithm=cfg["JWT_ALGORITHM"])
    return token, ttl * 60


def decode_access_token(token: str) -> dict:
    """Verify signature, algorithm, issuer, audience, expiry and required claims."""
    cfg = current_app.config
    try:
        claims = jwt.decode(
            token,
            cfg["SECRET_KEY"],
            algorithms=[cfg["JWT_ALGORITHM"]],  # pins the alg: blocks alg=none / RS->HS confusion
            audience=cfg["JWT_AUDIENCE"],
            issuer=cfg["JWT_ISSUER"],
            leeway=int(cfg["JWT_LEEWAY_SECONDS"]),
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired.", _www_auth("invalid_token")) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token.", _www_auth("invalid_token")) from exc
    return claims


def _www_auth(error: str) -> dict:
    return {"WWW-Authenticate": f'Bearer error="{error}"'}


def bearer_token_from_request() -> str:
    header = request.headers.get("Authorization", "")
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() != "bearer" or not credentials.strip():
        raise AuthError(
            "Missing or malformed Authorization header (expected 'Bearer <token>').",
            _www_auth("missing_token"),
        )
    return credentials.strip()


def jwt_required(view):
    """Middleware applied to every protected endpoint.

    It rejects the request when the header is absent, the signature is wrong,
    the token expired, or the subject no longer exists in the database.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        from .db import find_user_by_id  # local import: avoids a cycle

        claims = decode_access_token(bearer_token_from_request())
        try:
            user_id = int(claims["sub"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthError("Invalid token subject.", _www_auth("invalid_token")) from exc

        user = find_user_by_id(user_id)
        if user is None:
            # Token is cryptographically fine but the account is gone/revoked.
            raise AuthError("Account no longer exists.", _www_auth("invalid_token"))

        g.current_user = user
        g.jwt_claims = claims
        return view(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
# Multi-line fields (a post body) may contain tab/newline but no other ASCII
# control characters: those are never legitimate and are the raw material of
# log-injection and header-injection tricks.
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Single-line fields (a title) additionally reject tab, CR and LF.
NO_CONTROL_OR_NEWLINE_RE = re.compile(r"[\x00-\x1f\x7f]")


def validate_username(value: object) -> str:
    if not isinstance(value, str) or not USERNAME_RE.match(value):
        # Same generic message for "unknown user" and "bad format": no user
        # enumeration, no hint about the internal schema.
        raise AuthError("Invalid username or password.")
    return value


def validate_password_field(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AuthError("Invalid username or password.")
    if len(value.encode("utf-8")) > current_app.config.get("PASSWORD_MAX_BYTES", 72):
        raise AuthError("Invalid username or password.")
    return value


def validate_password_strength(value: object) -> str:
    min_len = current_app.config.get("PASSWORD_MIN_LENGTH", 8)
    if not isinstance(value, str) or len(value) < min_len:
        raise ValidationError(f"Password must be at least {min_len} characters long.")
    if len(value.encode("utf-8")) > current_app.config.get("PASSWORD_MAX_BYTES", 72):
        raise ValidationError("Password must be at most 72 bytes (bcrypt limit).")
    return value


def validate_text(value: object, field: str, *, min_len: int = 1,
                  max_len: int | None = None, allow_newlines: bool = True) -> str:
    max_len = max_len or current_app.config.get("MAX_TEXT_LENGTH", 2000)
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string.")
    text = value.strip()
    if len(text) < min_len:
        raise ValidationError(f"'{field}' must be at least {min_len} character(s) long.")
    if len(text) > max_len:
        raise ValidationError(f"'{field}' must be at most {max_len} characters long.")
    pattern = CONTROL_CHARS_RE if allow_newlines else NO_CONTROL_OR_NEWLINE_RE
    if pattern.search(text):
        raise ValidationError(f"'{field}' contains illegal control characters.")
    return text


def validate_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"'{field}' must be an integer.") from exc
    if not minimum <= number <= maximum:
        raise ValidationError(f"'{field}' must be between {minimum} and {maximum}.")
    return number


# ---------------------------------------------------------------------------
# Output encoding (XSS defence)
# ---------------------------------------------------------------------------

def escape_value(value):
    """Recursively HTML-escape every string that leaves the API.

    Stored data stays raw in the database (so it can be edited and re-used),
    but the API never emits ``<``, ``>``, ``&``, ``"`` or ``'`` unescaped.
    That is the "encode on output" rule from the OWASP XSS Prevention Cheat
    Sheet, and it makes stored and reflected XSS both inert for any HTML
    consumer.
    """
    if isinstance(value, str):
        return str(escape(value))
    if isinstance(value, dict):
        return {k: escape_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [escape_value(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Login rate limiting (brute-force defence, OWASP A07)
# ---------------------------------------------------------------------------

class LoginRateLimiter:
    """Fixed-window counter keyed by (client ip, username-FNV hash).

    In-process and therefore per-worker: good enough for a lab deployment and
    a deliberate talking point for the report (Redis would be the production
    answer).

    Two properties matter for memory safety:

    * a *read* never allocates an entry, so probing /auth/login with random
      usernames cannot grow the table (only a failed password does);
    * the table is bounded (``MAX_KEYS``), evicting expired buckets first and
      then the least recently used one.
    """

    MAX_KEYS = 5_000

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def _make_room(self, now: float, window: int) -> None:
        if len(self._hits) < self.MAX_KEYS:
            return
        for key in [k for k, b in self._hits.items() if not b or now - b[-1] > window]:
            del self._hits[key]
        overflow = len(self._hits) - self.MAX_KEYS + 1
        if overflow > 0:
            oldest = sorted(
                self._hits.items(), key=lambda kv: kv[1][-1] if kv[1] else 0.0
            )[:overflow]
            for key, _ in oldest:
                del self._hits[key]

    def check(self, key: tuple[str, str], max_attempts: int, window: int) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return  # nothing recorded for this key yet: no allocation
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= max_attempts:
                retry_after = int(window - (now - bucket[0])) + 1
                raise RateLimitError(
                    "Too many failed login attempts. Try again later.",
                    headers={"Retry-After": str(max(1, retry_after))},
                )

    def register_failure(self, key: tuple[str, str], window: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._make_room(now, window)
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            bucket.append(now)

    def reset(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._hits.pop(key, None)


login_limiter = LoginRateLimiter()


def client_key(username: str) -> tuple[str, str]:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    ip = ip.split(",")[0].strip()
    return (ip, username.lower())


def parse_json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Request body must be a JSON object.", status=400)
    return data
