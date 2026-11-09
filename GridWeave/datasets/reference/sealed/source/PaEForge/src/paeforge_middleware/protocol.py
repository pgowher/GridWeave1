"""Versioned, oracle-free transport contract for distributed PaEForge runs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from paeforge_contract import (
    read_verifier_bundle,
    validate_document,
    validate_verifier_bundle,
)
from paeforge_contract.canonical import sha256_digest
from paeforge_contract.leakage import scan_for_leakage

MIDDLEWARE_VERSION = "1.0.0"
ENVELOPE_SCHEMA_ID = "https://paeforge.local/schema/middleware-envelope/v1"
RESPONSE_SCHEMA_ID = "https://paeforge.local/schema/middleware-response/v1"
MEDIA_TYPE = "application/vnd.paeforge.exchange+json; version=1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class MiddlewareError(ValueError):
    """Safe, typed error that may cross the HTTP boundary."""

    def __init__(self, code: str, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def validate_idempotency_key(value: str | None) -> str:
    if value is None or not IDEMPOTENCY_PATTERN.fullmatch(value):
        raise MiddlewareError(
            "INVALID_IDEMPOTENCY_KEY",
            "X-PaEForge-Idempotency-Key must be 1-128 safe ASCII characters",
        )
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MiddlewareError("INVALID_ENVELOPE", f"{label} must be a JSON object")
    return value


def _verclo_policy_digest(policy: Mapping[str, Any]) -> str:
    """Reproduce frozen VERCLO v1 policy commitment without importing VERCLO."""

    encoded = json.dumps(
        policy,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"verclo-policy-profile-v1\x00" + encoded).hexdigest()


def validate_envelope(envelope: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """Fail closed on leakage, shape, exchange bindings, and policy binding."""

    try:
        scan_for_leakage(envelope)
        validate_document(envelope)
        exchange = _mapping(envelope.get("exchange"), "exchange")
        manifest = _mapping(exchange.get("case_manifest"), "exchange.case_manifest")
        observer = _mapping(
            exchange.get("observer_projection"), "exchange.observer_projection"
        )
        receipts = _mapping(exchange.get("receipt_stream"), "exchange.receipt_stream")
        policy = _mapping(envelope.get("policy"), "policy")
        validate_verifier_bundle(manifest, observer, receipts)
        if envelope["protocol_version"] != MIDDLEWARE_VERSION:
            raise MiddlewareError(
                "UNSUPPORTED_PROTOCOL", "unsupported middleware protocol version"
            )
        if _verclo_policy_digest(policy) != observer["policy"]["sha256"]:
            raise MiddlewareError(
                "POLICY_BINDING_MISMATCH",
                "policy digest does not match observer binding",
            )
        if policy.get("profile_id") != observer["policy"]["profile_id"]:
            raise MiddlewareError(
                "POLICY_BINDING_MISMATCH",
                "policy profile does not match observer binding",
            )
        if policy.get("version") != observer["policy"]["version"]:
            raise MiddlewareError(
                "POLICY_BINDING_MISMATCH",
                "policy version does not match observer binding",
            )
    except MiddlewareError:
        raise
    except Exception as exc:
        raise MiddlewareError("BOUNDARY_REJECTED", str(exc)) from exc
    return manifest, observer, receipts, policy


def build_envelope_from_run(run_root: str | Path, *, request_id: str) -> dict[str, Any]:
    """Build a transport envelope using public artifacts from a completed run.

    Oracle files are never read by this function.  The fixed paths below are the
    complete allowlist, which makes accidental directory-wide uploads impossible.
    """

    root = Path(run_root).resolve()
    manifest, observer, receipts = read_verifier_bundle(root / "verifier-input")
    policy = json.loads(
        (root / "configuration" / "policies" / "translated-policy.json").read_text(
            encoding="utf-8"
        )
    )
    config = json.loads(
        (root / "configuration" / "requested-config.json").read_text(encoding="utf-8")
    )
    identities = json.loads(
        (root / "configuration" / "source-identities.json").read_text(encoding="utf-8")
    )
    envelope = {
        "schema_id": ENVELOPE_SCHEMA_ID,
        "schema_version": "1.0.0",
        "protocol_version": MIDDLEWARE_VERSION,
        "request_id": request_id,
        "exchange": {
            "case_manifest": manifest,
            "observer_projection": observer,
            "receipt_stream": receipts,
        },
        "policy": policy,
        "execution": {
            "source_revision": identities["components"]["verclo"]["source_revision"],
            "configuration_sha256": sha256_digest(config["verclo"]),
        },
    }
    validate_envelope(envelope)
    return envelope


def envelope_digest(envelope: Mapping[str, Any]) -> str:
    return sha256_digest(envelope)


def raw_body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
