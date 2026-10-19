"""SQLite access layer.

Every statement in this module -- and in the whole application -- uses
parameter binding (``?`` placeholders).  No SQL string is ever built with
``%``, ``+`` or f-strings, which is what closes the door on SQL injection
(OWASP A03:2021 Injection).
"""
from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

log = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
"""

SEED_USERS = (
    # (username, plaintext password, role) -- demo accounts only.
    ("alice", "Passw0rd!Alice", "admin"),
    ("bob", "Passw0rd!Bob", "user"),
)

SEED_POSTS = (
    ("Welcome to the Lab 1 API", "This feed is served by a Flask + SQLite backend."),
    ("Security notes", "Passwords are hashed with bcrypt, sessions use short-lived JWTs."),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_db() -> sqlite3.Connection:
    """Return the per-request connection."""
    if "db" not in g:
        path = current_app.config["DATABASE"]
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        if exc is None:
            conn.commit()
        conn.close()


def init_db() -> None:
    """Create the schema and seed demo data if the database is empty."""
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()

    count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count:
        return

    # Imported late to avoid a circular import at module load time.
    from .security import hash_password

    for username, password, role in SEED_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, now_iso()),
        )

    alice_id = conn.execute("SELECT id FROM users WHERE username = ?", ("alice",)).fetchone()["id"]
    for title, body in SEED_POSTS:
        conn.execute(
            "INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)",
            (alice_id, title, body, now_iso()),
        )
    conn.commit()
    log.info("Database initialised with %d seed users", len(SEED_USERS))


def find_user_by_username(username: str) -> sqlite3.Row | None:
    """Parameterized lookup -- the username is data, never SQL."""
    return get_db().execute(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def find_user_by_id(user_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def list_posts(limit: int, offset: int, search: str | None) -> tuple[list[sqlite3.Row], int]:
    """Return one page of posts plus the total row count.

    ``search`` is bound as a parameter, so a payload such as
    ``' OR 1=1 --`` is matched as a literal substring and cannot widen the
    result set.
    """
    conn = get_db()
    if search:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM posts WHERE title LIKE ? OR body LIKE ?",
            (f"%{search}%", f"%{search}%"),
        ).fetchone()["n"]
        rows = conn.execute(
            """
            SELECT p.id, p.title, p.body, p.created_at, u.username AS author
            FROM posts p JOIN users u ON u.id = p.author_id
            WHERE p.title LIKE ? OR p.body LIKE ?
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
            """,
            (f"%{search}%", f"%{search}%", limit, offset),
        ).fetchall()
    else:
        total = conn.execute("SELECT COUNT(*) AS n FROM posts").fetchone()["n"]
        rows = conn.execute(
            """
            SELECT p.id, p.title, p.body, p.created_at, u.username AS author
            FROM posts p JOIN users u ON u.id = p.author_id
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return rows, total


def create_post(author_id: int, title: str, body: str) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (author_id, title, body, now_iso()),
    )
    conn.commit()
    return int(cur.lastrowid)
