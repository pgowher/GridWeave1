"""Public boundary-enforcement gateway; contains no VERCLO or evaluator imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections.abc import Mapping, Sequence
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from paeforge_contract import validate_document
from paeforge_contract.canonical import canonical_json_bytes

from .http_support import (
    IdempotencyStore,
    QuietHandler,
    read_json_request,
    require_bearer,
    send_json,
)
from .protocol import (
    MEDIA_TYPE,
    MIDDLEWARE_VERSION,
    RESPONSE_SCHEMA_ID,
    MiddlewareError,
    envelope_digest,
    validate_envelope,
    validate_idempotency_key,
)


def _forward(
    verifier_url: str,
    verifier_token: str,
    key: str,
    envelope: Mapping[str, Any],
    timeout_seconds: float,
) -> Mapping[str, Any]:
    request = Request(
        verifier_url.rstrip("/") + "/v1/evaluate",
        data=canonical_json_bytes(envelope),
        method="POST",
        headers={
            "Authorization": f"Bearer {verifier_token}",
            "Content-Type": MEDIA_TYPE,
            "X-PaEForge-Idempotency-Key": key,
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        raise MiddlewareError(
            "UPSTREAM_REJECTED", "verifier rejected the exchange", status=502
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise MiddlewareError(
            "UPSTREAM_UNAVAILABLE", "verifier is unavailable", status=503
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != {
        "protocol_version",
        "request_id",
        "result",
        "verifier_metrics",
    }:
        raise MiddlewareError(
            "INVALID_UPSTREAM_RESPONSE",
            "verifier returned an invalid response",
            status=502,
        )
    return payload


def normalize_verifier_urls(values: Sequence[str]) -> tuple[str, ...]:
    """Return a closed, unique verifier pool in stable configuration order."""

    urls: list[str] = []
    for raw in values:
        value = raw.strip().rstrip("/")
        if not value:
            continue
        if not value.startswith(("http://", "https://")):
            raise ValueError("verifier URLs must use http:// or https://")
        if value not in urls:
            urls.append(value)
    if not urls:
        raise ValueError("at least one verifier URL is required")
    return tuple(urls)


class VerifierPool:
    """Deterministically route an idempotency key to one verifier node.

    Stable key routing makes retries safe without claiming that the gateway's
    process-local cache is a distributed idempotency store.
    """

    def __init__(self, urls: Sequence[str]) -> None:
        self.urls = normalize_verifier_urls(urls)

    def select(self, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        return self.urls[int.from_bytes(digest[:8], "big") % len(self.urls)]

    def health(self, timeout_seconds: float = 2.0) -> dict[str, Any]:
        healthy = 0
        for url in self.urls:
            try:
                with urlopen(url + "/healthz", timeout=timeout_seconds) as response:
                    payload = json.loads(response.read())
                if response.status == 200 and payload.get("status") == "ok":
                    healthy += 1
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
                continue
        return {
            "configured_verifier_nodes": len(self.urls),
            "healthy_verifier_nodes": healthy,
            "routing": "sha256_idempotency_key",
        }


def make_handler(
    *,
    client_token: str,
    verifier_token: str,
    verifier_url: str | None = None,
    verifier_urls: Sequence[str] | None = None,
    timeout_seconds: float = 120.0,
    store: IdempotencyStore | None = None,
) -> type[QuietHandler]:
    cache = store or IdempotencyStore()
    configured_urls = verifier_urls or ((verifier_url,) if verifier_url else ())
    pool = VerifierPool(configured_urls)

    class GatewayHandler(QuietHandler):
        def do_GET(self) -> None:
            if self.path != "/healthz":
                self._error(
                    MiddlewareError("NOT_FOUND", "resource not found", status=404)
                )
                return
            cluster = pool.health()
            status = (
                200
                if cluster["healthy_verifier_nodes"]
                == cluster["configured_verifier_nodes"]
                else 503
            )
            send_json(
                self,
                status,
                {
                    "status": "ok" if status == 200 else "degraded",
                    "service": "paeforge-gateway",
                    "oracle_access": False,
                    "cluster": cluster,
                },
            )

        def do_POST(self) -> None:
            request_id = None
            try:
                if self.path != "/v1/evaluate":
                    raise MiddlewareError("NOT_FOUND", "resource not found", status=404)
                require_bearer(self, client_token)
                key = validate_idempotency_key(
                    self.headers.get("X-PaEForge-Idempotency-Key")
                )
                envelope, body = read_json_request(self)
                request_id = str(envelope.get("request_id", "")) or None
                digest = envelope_digest(envelope)
                cached = cache.get(key, digest)
                if cached is not None:
                    send_json(
                        self, 200, cached, headers={"X-PaEForge-Replayed": "true"}
                    )
                    return

                validation_started = time.perf_counter_ns()
                manifest, _, _, _ = validate_envelope(envelope)
                validation_ns = time.perf_counter_ns() - validation_started
                forward_started = time.perf_counter_ns()
                upstream = _forward(
                    pool.select(key), verifier_token, key, envelope, timeout_seconds
                )
                forward_ns = time.perf_counter_ns() - forward_started
                if upstream["request_id"] != envelope["request_id"]:
                    raise MiddlewareError(
                        "INVALID_UPSTREAM_RESPONSE",
                        "request identity mismatch",
                        status=502,
                    )
                result = upstream["result"]
                validate_document(result)
                if (
                    result["exchange_id"] != manifest["exchange_id"]
                    or result["case_id"] != manifest["case_id"]
                ):
                    raise MiddlewareError(
                        "INVALID_UPSTREAM_RESPONSE",
                        "exchange identity mismatch",
                        status=502,
                    )
                response = {
                    "schema_id": RESPONSE_SCHEMA_ID,
                    "schema_version": "1.0.0",
                    "protocol_version": MIDDLEWARE_VERSION,
                    "request_id": envelope["request_id"],
                    "exchange_id": manifest["exchange_id"],
                    "case_id": manifest["case_id"],
                    "result": result,
                    "enforcement": {
                        "input_sha256": digest,
                        "payload_bytes": len(body),
                        "gateway_validation_ns": validation_ns,
                        "gateway_forward_ns": forward_ns,
                        "verifier_validation_ns": upstream["verifier_metrics"][
                            "verifier_validation_ns"
                        ],
                        "verifier_execution_ns": upstream["verifier_metrics"][
                            "verifier_execution_ns"
                        ],
                        "hop_count": 2,
                        "oracle_fields_rejected": True,
                    },
                }
                validate_document(response)
                cache.put(key, digest, response)
                send_json(self, 200, response, headers={"X-PaEForge-Replayed": "false"})
            except MiddlewareError as exc:
                self._error(exc, request_id)
            except Exception:  # noqa: BLE001 - HTTP boundary must fail closed without a traceback.
                self._error(
                    MiddlewareError(
                        "BOUNDARY_FAILURE", "boundary failed closed", status=422
                    ),
                    request_id,
                )

    return GatewayHandler


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the PaEForge boundary gateway")
    parser.add_argument(
        "--host", default=os.environ.get("PAEFORGE_GATEWAY_HOST", "0.0.0.0")
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("PAEFORGE_GATEWAY_PORT", "8080"))
    )
    parser.add_argument(
        "--verifier-url",
        default=os.environ.get("PAEFORGE_VERIFIER_URL", "http://verifier:8081"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    client_token = os.environ.get("PAEFORGE_CLIENT_TOKEN", "")
    verifier_token = os.environ.get("PAEFORGE_VERIFIER_TOKEN", "")
    if len(client_token) < 16 or len(verifier_token) < 16:
        raise SystemExit("both PaEForge tokens must contain at least 16 characters")
    configured = os.environ.get("PAEFORGE_VERIFIER_URLS", "")
    verifier_urls = configured.split(",") if configured else [args.verifier_url]
    handler = make_handler(
        client_token=client_token,
        verifier_token=verifier_token,
        verifier_urls=verifier_urls,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
