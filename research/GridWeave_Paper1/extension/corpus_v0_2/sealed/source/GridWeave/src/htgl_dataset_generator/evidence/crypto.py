"""Deterministic synthetic cryptographic fixture primitives."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from htgl_dataset_generator.seeds import CounterRng, content_id

from .fixtures import SyntheticKeyFixture
from .profiles import ReceiptProfile


AUTH_DOMAIN = b"HTGL-EVIDENCE-AUTHENTICATOR-v1\x00"


@dataclass(frozen=True)
class DerivedSyntheticKey:
    fixture: SyntheticKeyFixture
    secret: bytes


def derive_synthetic_key(
    rng: CounterRng,
    *,
    subject_actor_id: str,
    primitive: str,
    algorithm: str,
    key_role: str = "issuer",
    context_id: str = "stable",
) -> DerivedSyntheticKey:
    """Derive a reproducible evaluator key without releasing secret material."""

    if primitive not in {"hmac", "signature"}:
        raise ValueError(f"synthetic keys are not defined for primitive={primitive!r}")
    if key_role not in {"issuer", "adversary"}:
        raise ValueError(f"unsupported synthetic key_role={key_role!r}")
    label = f"synthetic-key|{key_role}|{subject_actor_id}|{primitive}|{context_id}"
    secret = rng.bytes(label, 0, 32)
    public_key_hex: str | None = None
    if primitive == "signature":
        public_key_hex = (
            Ed25519PrivateKey.from_private_bytes(secret)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
    secret_digest = hashlib.sha256(secret).hexdigest()
    key_id = content_id(
        "synthetic_evidence_key",
        {
            "algorithm": algorithm,
            "context_id": context_id,
            "key_role": key_role,
            "primitive": primitive,
            "public_key_hex": public_key_hex,
            "secret_material_sha256": secret_digest,
            "subject_actor_id": subject_actor_id,
        },
    )
    return DerivedSyntheticKey(
        fixture=SyntheticKeyFixture(
            key_id=key_id,
            key_role=key_role,
            subject_actor_id=subject_actor_id,
            primitive=primitive,
            algorithm=algorithm,
            public_key_hex=public_key_hex,
            secret_material_sha256=secret_digest,
        ),
        secret=secret,
    )


def authenticate(profile: ReceiptProfile, payload: bytes, key: DerivedSyntheticKey | None) -> bytes:
    message = _message(profile, payload)
    if profile.primitive == "digest":
        if key is not None:
            raise ValueError("digest profile must not receive a key")
        return hashlib.sha256(message).digest()
    if profile.primitive == "hmac":
        if key is None:
            raise ValueError("HMAC profile requires a synthetic key")
        return hmac.new(key.secret, message, hashlib.sha256).digest()
    if profile.primitive == "signature":
        if key is None:
            raise ValueError("signature profile requires a synthetic key")
        return Ed25519PrivateKey.from_private_bytes(key.secret).sign(message)
    if profile.primitive == "merkle_inclusion":
        if key is not None:
            raise ValueError("Merkle inclusion profile must not receive a key")
        return hashlib.sha256(message).digest()
    raise ValueError(f"unsupported primitive={profile.primitive!r}")


def verify_authenticator(
    profile: ReceiptProfile,
    payload: bytes,
    authenticator: bytes,
    key: DerivedSyntheticKey | None,
) -> bool:
    message = _message(profile, payload)
    if profile.primitive in {"digest", "merkle_inclusion"}:
        return hmac.compare_digest(authenticator, hashlib.sha256(message).digest())
    if key is None:
        return False
    if profile.primitive == "hmac":
        expected = hmac.new(key.secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(authenticator, expected)
    if profile.primitive == "signature":
        if key.fixture.public_key_hex is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.fixture.public_key_hex)).verify(
                authenticator, message
            )
        except (InvalidSignature, ValueError):
            return False
        return True
    return False


def _message(profile: ReceiptProfile, payload: bytes) -> bytes:
    return AUTH_DOMAIN + len(profile.profile_id).to_bytes(4, "big") + profile.profile_id.encode("utf-8") + payload

