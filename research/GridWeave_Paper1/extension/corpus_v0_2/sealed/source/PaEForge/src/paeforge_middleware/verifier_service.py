"""Oracle-blind network service that owns the VERCLO runtime."""

from __future__ import annotations

import argparse
import os
import tempfile
import time
from collections.abc import Mapping, Sequence
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from paeforge_contract import write_verifier_bundle
from paeforge_pipeline.io import write_json

from .http_support import (
    IdempotencyStore,
    QuietHandler,
    read_json_request,
    require_bearer,
    send_json,
)
from .protocol import (
    MiddlewareError,
    envelope_digest,
    validate_envelope,
    validate_idempotency_key,
)


def evaluate_envelope(
    envelope: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, int]]:
    validation_started = time.perf_counter_ns()
    manifest, observer, receipts, policy = validate_envelope(envelope)
    validation_ns = time.perf_counter_ns() - validation_started
    with tempfile.TemporaryDirectory(prefix="paeforge-network-verifier-") as temporary:
        root = Path(temporary)
        write_verifier_bundle(root / "input", manifest, observer, receipts)
        write_json(root / "policies" / "policy.json", policy)
        execution_started = time.perf_counter_ns()
        # Lazy import keeps this module inspectable without loading VERCLO in gateway code.
        from paeforge_pipeline.verclo_worker import evaluate_bundle

        result = evaluate_bundle(
            root / "input",
            root / "policies",
            source_revision=envelope["execution"]["source_revision"],
            configuration_sha256=envelope["execution"]["configuration_sha256"],
        )
        execution_ns = time.perf_counter_ns() - execution_started
    return result, {
        "verifier_validation_ns": validation_ns,
        "verifier_execution_ns": execution_ns,
    }


def make_handler(
    token: str, store: IdempotencyStore | None = None
) -> type[QuietHandler]:
    cache = store or IdempotencyStore()

    class VerifierHandler(QuietHandler):
        def do_GET(self) -> None:
            if self.path != "/healthz":
                self._error(
                    MiddlewareError("NOT_FOUND", "resource not found", status=404)
                )
                return
            send_json(
                self,
                200,
                {
                    "status": "ok",
                    "service": "paeforge-verifier",
                    "oracle_access": False,
                },
            )

        def do_POST(self) -> None:
            request_id = None
            try:
                if self.path != "/v1/evaluate":
                    raise MiddlewareError("NOT_FOUND", "resource not found", status=404)
                require_bearer(self, token)
                key = validate_idempotency_key(
                    self.headers.get("X-PaEForge-Idempotency-Key")
                )
                envelope, _ = read_json_request(self)
                request_id = str(envelope.get("request_id", "")) or None
                digest = envelope_digest(envelope)
                cached = cache.get(key, digest)
                if cached is not None:
                    send_json(
                        self, 200, cached, headers={"X-PaEForge-Replayed": "true"}
                    )
                    return
                result, metrics = evaluate_envelope(envelope)
                response = {
                    "protocol_version": "1.0.0",
                    "request_id": envelope["request_id"],
                    "result": result,
                    "verifier_metrics": metrics,
                }
                cache.put(key, digest, response)
                send_json(self, 200, response, headers={"X-PaEForge-Replayed": "false"})
            except MiddlewareError as exc:
                self._error(exc, request_id)
            except Exception:  # noqa: BLE001 - HTTP boundary must fail closed without a traceback.
                self._error(
                    MiddlewareError(
                        "VERIFIER_FAILURE", "verifier failed closed", status=422
                    ),
                    request_id,
                )

    return VerifierHandler


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the oracle-blind PaEForge verifier service"
    )
    parser.add_argument(
        "--host", default=os.environ.get("PAEFORGE_VERIFIER_HOST", "0.0.0.0")
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PAEFORGE_VERIFIER_PORT", "8081")),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    token = os.environ.get("PAEFORGE_VERIFIER_TOKEN", "")
    if len(token) < 16:
        raise SystemExit("PAEFORGE_VERIFIER_TOKEN must contain at least 16 characters")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(token))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
