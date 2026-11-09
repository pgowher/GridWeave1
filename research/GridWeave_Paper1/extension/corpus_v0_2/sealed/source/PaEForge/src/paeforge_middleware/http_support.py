"""Small standard-library HTTP primitives shared by both services."""

from __future__ import annotations

import hmac
import json
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler
from typing import Any

from paeforge_contract.canonical import canonical_json_bytes

from .protocol import MAX_REQUEST_BYTES, MiddlewareError


def require_bearer(handler: BaseHTTPRequestHandler, expected_token: str) -> None:
    supplied = handler.headers.get("Authorization", "")
    expected = f"Bearer {expected_token}"
    if not expected_token or not hmac.compare_digest(supplied, expected):
        raise MiddlewareError(
            "UNAUTHORIZED", "valid bearer authentication is required", status=401
        )


def read_json_request(
    handler: BaseHTTPRequestHandler,
) -> tuple[Mapping[str, Any], bytes]:
    content_type = (
        handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    )
    if content_type not in {
        "application/json",
        "application/vnd.paeforge.exchange+json",
    }:
        raise MiddlewareError(
            "UNSUPPORTED_MEDIA_TYPE",
            "request must use the PaEForge JSON media type",
            status=415,
        )
    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        raise MiddlewareError(
            "LENGTH_REQUIRED", "Content-Length is required", status=411
        )
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise MiddlewareError(
            "INVALID_LENGTH", "Content-Length must be an integer"
        ) from exc
    if length < 1 or length > MAX_REQUEST_BYTES:
        raise MiddlewareError(
            "PAYLOAD_TOO_LARGE",
            f"payload limit is {MAX_REQUEST_BYTES} bytes",
            status=413,
        )
    body = handler.rfile.read(length)
    if len(body) != length:
        raise MiddlewareError(
            "TRUNCATED_REQUEST", "request body is shorter than Content-Length"
        )
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MiddlewareError(
            "INVALID_JSON", "request body is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(payload, Mapping):
        raise MiddlewareError("INVALID_JSON", "request body must be a JSON object")
    return payload, body


def send_json(
    handler: BaseHTTPRequestHandler,
    status: int,
    payload: Mapping[str, Any],
    *,
    headers: Mapping[str, str] | None = None,
) -> None:
    encoded = canonical_json_bytes(payload)
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    if headers:
        for name, value in headers.items():
            handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(encoded)


class IdempotencyStore:
    """Bounded process-local replay cache with conflict detection."""

    def __init__(self, maximum_entries: int = 1024) -> None:
        self.maximum_entries = maximum_entries
        self._rows: dict[str, tuple[str, Mapping[str, Any]]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, digest: str) -> Mapping[str, Any] | None:
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                return None
            prior_digest, response = row
            if prior_digest != digest:
                raise MiddlewareError(
                    "IDEMPOTENCY_CONFLICT",
                    "idempotency key was already used for a different payload",
                    status=409,
                )
            return response

    def put(self, key: str, digest: str, response: Mapping[str, Any]) -> None:
        with self._lock:
            if key in self._rows:
                prior_digest, _ = self._rows[key]
                if prior_digest != digest:
                    raise MiddlewareError(
                        "IDEMPOTENCY_CONFLICT", "idempotency conflict", status=409
                    )
                return
            if len(self._rows) >= self.maximum_entries:
                self._rows.pop(next(iter(self._rows)))
            self._rows[key] = (digest, dict(response))


class QuietHandler(BaseHTTPRequestHandler):
    server_version = "PaEForgeMiddleware/1.0"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Structured deployment logs belong at the orchestration layer; never log bodies.
        return

    def _error(self, exc: MiddlewareError, request_id: str | None = None) -> None:
        payload: dict[str, Any] = {"error": {"code": exc.code, "message": str(exc)}}
        if request_id:
            payload["request_id"] = request_id
        send_json(self, exc.status, payload)
