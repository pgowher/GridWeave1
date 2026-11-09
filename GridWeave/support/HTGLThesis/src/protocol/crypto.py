"""Cryptographic profile for authenticated C-PaE messages.

The wire schema deliberately keeps cryptographic material algorithm-neutral.  This
module supplies the normative C-PAE-CRYPTO-1.1 profile: RFC 8785 canonicalisation
for the integer-only C-PaE JSON vocabulary, SHA-256 body commitments, key/role
binding, event-time key validity, and signature verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import copy
import hashlib
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils


DOMAIN = "C-PAE-MESSAGE-v1"
MAX_SAFE_INTEGER = (1 << 53) - 1
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)

SIGNED_FIELDS = (
    "schema_id",
    "protocol_version",
    "model_version",
    "message_id",
    "message_type",
    "sender",
    "recipients",
    "sequence_number",
    "nonce",
    "claimed_event_time",
    "emitted_at",
    "body_digest",
    "previous_message_digest",
)


def _string(value: str) -> bytes:
    # Python's encoder gives the RFC 8259 escaping required by JCS.  Encoding the
    # result rejects lone surrogate code points, which I-JSON also forbids.
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return encoded.encode("utf-8", errors="strict")


def _property_order(value: str) -> bytes:
    # RFC 8785 sorts object properties by their UTF-16 code units.
    return value.encode("utf-16-be", errors="strict")


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 bytes for the C-PaE JSON profile.

    C-PaE schemas contain integers but no binary floating-point fields.  Rejecting
    floats avoids cross-runtime number ambiguity; integers are restricted to the
    I-JSON interoperable range used by ECMAScript JSON numbers.
    """

    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("MALFORMED_CANONICAL_PAYLOAD")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("MALFORMED_CANONICAL_PAYLOAD")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(canonicalize(item) for item in value) + b"]"
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("MALFORMED_CANONICAL_PAYLOAD")
        keys = sorted(value, key=_property_order)
        fields = (_string(key) + b":" + canonicalize(value[key]) for key in keys)
        return b"{" + b",".join(fields) + b"}"
    raise ValueError("MALFORMED_CANONICAL_PAYLOAD")


def body_digest(body: Any) -> str:
    return hashlib.sha256(canonicalize(body)).hexdigest()


def signed_payload(message: Mapping[str, Any]) -> bytes:
    """Construct the domain-separated, immutable C-PaE signature input."""

    signature = message["signature"]
    protected = {field: message[field] for field in SIGNED_FIELDS}
    protected["signature_algorithm"] = signature["algorithm"]
    protected["canonicalization"] = signature["canonicalization"]
    protected["signature_domain"] = signature["domain"]
    return DOMAIN.encode("ascii") + b"\x00" + canonicalize(protected)


def message_digest(message: Mapping[str, Any]) -> str:
    """Digest the immutable sender representation for chaining/idempotence.

    Recipient-owned observations are deliberately absent, so the sender can form
    the next predecessor reference before any recipient records delivery state.
    """

    immutable = {field: message[field] for field in SIGNED_FIELDS}
    immutable["signature"] = message["signature"]
    immutable["body"] = message["body"]
    return hashlib.sha256(canonicalize(immutable)).hexdigest()


def _decode_base64url(value: str) -> bytes:
    if "=" in value:
        raise ValueError("INVALID_SIGNATURE")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("INVALID_SIGNATURE") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("INVALID_SIGNATURE")
    return raw


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("CREDENTIAL_INVALID_AT_EVENT")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    principal_id: str
    organization_id: str
    roles: frozenset[str]
    algorithm: str
    public_key: bytes
    valid_from: datetime
    valid_until: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        for value in (self.valid_from, self.valid_until, self.revoked_at):
            if value is not None and value.tzinfo is None:
                raise ValueError("key validity times must be timezone-aware")
        if self.valid_from >= self.valid_until:
            raise ValueError("key validity interval must be non-empty")


class KeyRegistry:
    """Small deterministic registry interface used by the protocol verifier."""

    def __init__(self, records: tuple[KeyRecord, ...] | list[KeyRecord] = ()) -> None:
        self._records: dict[str, KeyRecord] = {}
        for record in records:
            self.register(record)

    def register(self, record: KeyRecord) -> None:
        if record.key_id in self._records:
            raise ValueError("duplicate key_id")
        self._records[record.key_id] = record

    def resolve(self, key_id: str) -> KeyRecord:
        try:
            return self._records[key_id]
        except KeyError as exc:
            raise ValueError("UNKNOWN_KEY") from exc


def _load_public_key(record: KeyRecord):
    data = record.public_key
    if record.algorithm == "Ed25519" and len(data) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(data)
    try:
        return serialization.load_pem_public_key(data)
    except ValueError:
        try:
            return serialization.load_der_public_key(data)
        except ValueError as exc:
            raise ValueError("INVALID_SIGNATURE") from exc


def _verify_signature(algorithm: str, public_key: Any, signature: bytes, data: bytes) -> None:
    try:
        if algorithm == "Ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
            return
        if algorithm == "ECDSA-P256-SHA256" and isinstance(public_key, ec.EllipticCurvePublicKey):
            if not isinstance(public_key.curve, ec.SECP256R1):
                raise ValueError("INVALID_SIGNATURE")
            r, s = utils.decode_dss_signature(signature)
            if r <= 0 or s <= 0 or s > P256_ORDER // 2:
                raise ValueError("INVALID_SIGNATURE")
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return
        if algorithm == "RSA-PSS-SHA256" and isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                raise ValueError("INVALID_SIGNATURE")
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
            return
        raise ValueError("INVALID_SIGNATURE")
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("INVALID_SIGNATURE") from exc


def verify_authenticated_message(message: Mapping[str, Any], registry: KeyRegistry) -> str:
    """Authenticate a structurally valid message and return its replay digest."""

    from .validation import validate_message

    validate_message(message)
    try:
        expected_digest = body_digest(message["body"])
    except (UnicodeError, ValueError) as exc:
        raise ValueError("MALFORMED_CANONICAL_PAYLOAD") from exc
    if message["body_digest"] != expected_digest:
        raise ValueError("BODY_DIGEST_MISMATCH")

    sender = message["sender"]
    record = registry.resolve(str(sender["key_id"]))
    if (
        record.principal_id != sender["principal_id"]
        or record.organization_id != sender["organization_id"]
        or sender["role"] not in record.roles
        or record.algorithm != message["signature"]["algorithm"]
    ):
        raise ValueError("CREDENTIAL_INVALID_AT_EVENT")
    event_time = _instant(str(message["claimed_event_time"]))
    valid_from = record.valid_from.astimezone(timezone.utc)
    valid_until = record.valid_until.astimezone(timezone.utc)
    revoked_at = record.revoked_at.astimezone(timezone.utc) if record.revoked_at else None
    if event_time < valid_from or event_time >= valid_until or (
        revoked_at is not None and event_time >= revoked_at
    ):
        raise ValueError("CREDENTIAL_INVALID_AT_EVENT")

    signature = _decode_base64url(str(message["signature"]["value"]))
    _verify_signature(record.algorithm, _load_public_key(record), signature, signed_payload(message))
    return message_digest(message)


def sign_message(message: Mapping[str, Any], private_key: Any) -> dict[str, Any]:
    """Return a signed copy of a schema-shaped message (primarily for adapters/tests)."""

    result = copy.deepcopy(dict(message))
    result["body_digest"] = body_digest(result["body"])
    algorithm = result["signature"]["algorithm"]
    payload = signed_payload(result)
    if algorithm == "Ed25519" and isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(payload)
    elif algorithm == "ECDSA-P256-SHA256" and isinstance(private_key, ec.EllipticCurvePrivateKey):
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("unsupported private key")
        signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        if s > P256_ORDER // 2:
            signature = utils.encode_dss_signature(r, P256_ORDER - s)
    elif algorithm == "RSA-PSS-SHA256" and isinstance(private_key, rsa.RSAPrivateKey):
        if private_key.key_size < 2048:
            raise ValueError("unsupported private key")
        signature = private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    else:
        raise ValueError("unsupported private key")
    result["signature"]["value"] = _encode_base64url(signature)
    return result


def public_key_bytes(public_key: Any) -> bytes:
    """Encode a supported public key for a :class:`KeyRecord`."""

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
