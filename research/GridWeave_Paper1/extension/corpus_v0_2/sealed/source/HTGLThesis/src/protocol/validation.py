"""Schema and cross-field validation for C-PaE v1 messages."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

if TYPE_CHECKING:
    from .crypto import KeyRegistry


ROOT = Path(__file__).resolve().parent
MESSAGE_SCHEMA = ROOT / "cpae_message_v1.schema.json"
REJECTION_CATALOG = ROOT / "cpae_rejection_codes_v1.json"


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_message(message: Mapping[str, Any]) -> None:
    """Validate transport shape and protocol-level cross-field invariants."""

    schema = json.loads(MESSAGE_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(message)
    claimed = _time(str(message["claimed_event_time"]))
    emitted = _time(str(message["emitted_at"]))
    received = message["received_at"]
    if claimed > emitted:
        raise ValueError("CLAIMED_TIME_AFTER_EMISSION")
    if received is not None and _time(str(received)) < emitted:
        raise ValueError("RECEIPT_TIME_BEFORE_EMISSION")
    sequence = int(message["sequence_number"])
    predecessor = message["previous_message_digest"]
    if sequence == 0 and predecessor is not None:
        raise ValueError("PREDECESSOR_MISMATCH")
    if sequence > 0 and predecessor is None:
        raise ValueError("PREDECESSOR_MISMATCH")
    body = message["body"]
    if message["message_type"] == "EVIDENCE_VALIDATION":
        if body["status"] == "GRADED" and (body["grade"] is None or body["rejection_code"] is not None):
            raise ValueError("MALFORMED_MESSAGE")
        if body["status"] == "REJECTED" and (body["grade"] is not None or body["rejection_code"] is None):
            raise ValueError("MALFORMED_MESSAGE")
        known_rejections = {
            row["code"]
            for row in json.loads(REJECTION_CATALOG.read_text(encoding="utf-8"))["rejection_codes"]
        }
        if body["rejection_code"] is not None and body["rejection_code"] not in known_rejections:
            raise ValueError("MALFORMED_MESSAGE")
    if message["message_type"] == "EXCEPTION_ASSERT":
        if _time(body["effective_at"]) >= _time(body["expires_at"]):
            raise ValueError("EXCEPTION_EXPIRED")
    if message["message_type"] == "CLOSURE_DECISION":
        missing_baseline = body["scope_version"] is None or body["obligation_version"] is None
        if missing_baseline and body["outcome"] not in {"UNVERIFIABLE", "IN_PROGRESS"}:
            raise ValueError("BASELINE_UNVERIFIABLE")


class ReplayGuard:
    """In-memory conformance guard for sender/key replay and continuity rules."""

    def __init__(self, key_registry: "KeyRegistry | None" = None) -> None:
        self._streams: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
        self._nonces: set[tuple[str, str, str]] = set()
        self._key_registry = key_registry

    def accept(
        self,
        message: Mapping[str, Any],
        canonical_message_digest: str | None = None,
    ) -> str:
        if self._key_registry is not None:
            from .crypto import verify_authenticated_message

            verified_digest = verify_authenticated_message(message, self._key_registry)
            if canonical_message_digest is not None and canonical_message_digest != verified_digest:
                raise ValueError("BODY_DIGEST_MISMATCH")
            canonical_message_digest = verified_digest
        else:
            validate_message(message)
            if canonical_message_digest is None:
                raise ValueError("VERIFICATION_MATERIAL_UNAVAILABLE")
        sender = message["sender"]
        stream = (str(sender["principal_id"]), str(sender["key_id"]))
        rows = self._streams.setdefault(stream, [])
        sequence = int(message["sequence_number"])
        message_id = str(message["message_id"])
        nonce_key = (*stream, str(message["nonce"]))
        for prior_id, prior_digest, _ in rows:
            if prior_id == message_id:
                if prior_digest == canonical_message_digest:
                    return "IDEMPOTENT_REPLAY"
                raise ValueError("MESSAGE_ID_REUSE")
        if nonce_key in self._nonces:
            raise ValueError("NONCE_REUSE")
        if sequence < len(rows):
            raise ValueError("SEQUENCE_REGRESSION")
        if sequence > len(rows):
            raise ValueError("SEQUENCE_GAP")
        if rows and message["previous_message_digest"] != rows[-1][1]:
            raise ValueError("PREDECESSOR_MISMATCH")
        rows.append((message_id, canonical_message_digest, str(message["nonce"])))
        self._nonces.add(nonce_key)
        return "ACCEPTED"


class AuthenticatedReplayGuard(ReplayGuard):
    """Replay guard that cannot be constructed without a cryptographic key registry."""

    def __init__(self, key_registry: "KeyRegistry") -> None:
        super().__init__(key_registry=key_registry)

    def accept(self, message: Mapping[str, Any]) -> str:  # type: ignore[override]
        return super().accept(message)
