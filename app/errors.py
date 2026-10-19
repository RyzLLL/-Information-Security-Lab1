"""Typed API errors + JSON error handlers.

Every error leaves the API as JSON and never leaks a stack trace, a SQL
statement or an internal path -- that is part of A05:2021 Security
Misconfiguration / information disclosure.
"""
from __future__ import annotations

import logging

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

log = logging.getLogger(__name__)


class ApiError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str, status: int | None = None,
                 code: str | None = None, headers: dict | None = None):
        super().__init__(message)
        self.message = message
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code
        self.headers = headers or {}


class ValidationError(ApiError):
    status = 400
    code = "validation_error"


class AuthError(ApiError):
    status = 401
    code = "unauthorized"

    def __init__(self, message: str, headers: dict | None = None):
        super().__init__(message, headers=headers or {})


class RateLimitError(ApiError):
    status = 429
    code = "too_many_requests"


def error_response(code: str, message: str, status: int, headers: dict | None = None):
    resp = jsonify({"error": {"code": code, "message": message}})
    resp.status_code = status
    for key, value in (headers or {}).items():
        resp.headers[key] = value
    return resp


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def handle_api_error(err: ApiError):
        resp = jsonify({"error": {"code": err.code, "message": err.message}})
        resp.status_code = err.status
        for key, value in err.headers.items():
            resp.headers[key] = value
        return resp

    @app.errorhandler(HTTPException)
    def handle_http_error(err: HTTPException):
        # Keep Flask's status but replace the default HTML body with JSON.
        return error_response(err.name.lower().replace(" ", "_"), err.description, err.code)

    @app.errorhandler(Exception)
    def handle_unexpected(err: Exception):
        log.exception("Unhandled error on %s %s", request.method, request.path)
        return error_response(
            "internal_error",
            "An unexpected error occurred. The incident has been logged.",
            500,
        )
