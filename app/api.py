"""Protected data endpoints.

GET  /api/data   -- read the post feed (restricted to authenticated users)
POST /api/posts  -- create a post (the "own method" required by the lab)
GET  /api/me     -- return the caller's identity decoded from the JWT
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from .db import create_post as db_create_post
from .db import list_posts
from .security import (
    escape_value,
    jwt_required,
    parse_json_body,
    validate_int,
    validate_text,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.get("/data")
@jwt_required
def get_data():
    """Return a page of posts.

    Query parameters:
      limit  (1..100, default 50)
      offset (>=0, default 0)
      q      optional substring filter
    """
    limit = validate_int(request.args.get("limit", 50), "limit", minimum=1, maximum=100)
    offset = validate_int(request.args.get("offset", 0), "offset", minimum=0, maximum=10_000)
    search = request.args.get("q")
    if search is not None and search != "":
        search = validate_text(search, "q", max_len=200)
    else:
        search = None

    rows, total = list_posts(limit=limit, offset=offset, search=search)
    items = [
        {
            "id": row["id"],
            "title": row["title"],
            "body": row["body"],
            "author": row["author"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    body = {
        "total": total,
        "limit": limit,
        "offset": offset,
        # Output encoding happens here, at the trust boundary.
        "data": escape_value(items),
    }
    return jsonify(body), 200


@api_bp.post("/posts")
@jwt_required
def create_post():
    """Create a post owned by the authenticated user.

    Body: {"title": "...", "body": "..."}
    """
    data = parse_json_body()
    title = validate_text(
        data.get("title"), "title", min_len=3, max_len=120, allow_newlines=False
    )
    text = validate_text(data.get("body"), "body", min_len=1, max_len=2000)

    post_id = db_create_post(g.current_user["id"], title, text)
    return (
        jsonify(
            message="Post created.",
            post={
                "id": post_id,
                "title": escape_value(title),
                "body": escape_value(text),
                "author": escape_value(g.current_user["username"]),
            },
        ),
        201,
    )


@api_bp.get("/me")
@jwt_required
def me():
    user = g.current_user
    return jsonify(
        id=user["id"],
        username=escape_value(user["username"]),
        role=user["role"],
        token_expires_at=g.jwt_claims.get("exp"),
    )
