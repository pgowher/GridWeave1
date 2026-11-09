"""Authenticated client for submitting only the allowlisted public exchange."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from paeforge_contract import validate_document
from paeforge_contract.canonical import canonical_json_bytes

from .protocol import (
    MEDIA_TYPE,
    MiddlewareError,
    build_envelope_from_run,
    validate_idempotency_key,
)


def submit_envelope(
    gateway_url: str,
    token: str,
    idempotency_key: str,
    envelope: Mapping[str, Any],
    *,
    timeout_seconds: float = 120.0,
) -> Mapping[str, Any]:
    validate_idempotency_key(idempotency_key)
    request = Request(
        gateway_url.rstrip("/") + "/v1/evaluate",
        data=canonical_json_bytes(envelope),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": MEDIA_TYPE,
            "X-PaEForge-Idempotency-Key": idempotency_key,
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error", {})
            message = str(detail.get("message", "gateway rejected request"))
            code = str(detail.get("code", "GATEWAY_REJECTED"))
        except (
            AttributeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            message, code = "gateway rejected request", "GATEWAY_REJECTED"
        raise MiddlewareError(code, message, status=exc.code) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise MiddlewareError(
            "GATEWAY_UNAVAILABLE", "gateway is unavailable", status=503
        ) from exc
    if not isinstance(payload, Mapping):
        raise MiddlewareError(
            "INVALID_GATEWAY_RESPONSE", "gateway returned invalid JSON", status=502
        )
    validate_document(payload)
    validate_document(payload["result"])
    if payload["result"]["exchange_id"] != payload["exchange_id"]:
        raise MiddlewareError(
            "INVALID_GATEWAY_RESPONSE", "result exchange identity mismatch", status=502
        )
    if payload["result"]["case_id"] != payload["case_id"]:
        raise MiddlewareError(
            "INVALID_GATEWAY_RESPONSE", "result case identity mismatch", status=502
        )
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Submit a completed PaEForge run to a boundary gateway"
    )
    parser.add_argument("run_root", type=Path)
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("PAEFORGE_GATEWAY_URL", "http://127.0.0.1:8080"),
    )
    parser.add_argument("--token", default=os.environ.get("PAEFORGE_CLIENT_TOKEN", ""))
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--idempotency-key")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.token:
        raise SystemExit("set PAEFORGE_CLIENT_TOKEN or pass --token")
    envelope = build_envelope_from_run(args.run_root, request_id=args.request_id)
    response = submit_envelope(
        args.gateway_url,
        args.token,
        args.idempotency_key or args.request_id,
        envelope,
    )
    encoded = canonical_json_bytes(response)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as handle:
            handle.write(encoded)
    else:
        print(encoded.decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
