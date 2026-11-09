"""Authenticated TCP trust-anchor services and a network PBFT client.

The services use loopback or routable HTTP endpoints, but keep transport and
evidence semantics separate: every response is cryptographically bound to the
receipt commitment and the complete :class:`BackendValidation` decision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, replace
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from evidence.models import BackendValidation, CustodianReceipt
from verclo.models import Obligation

from .validation_backend import (
    committee_digest,
    PBFTSignedVote,
    PBFTValidationBackend,
    PBFTValidationCertificate,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if "=" in value:
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64(raw) != value:
        raise ValueError("non-canonical base64url")
    return raw


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    """Create reproducible experiment keys; deployments must inject managed keys."""

    seed = hashlib.sha256(b"VERCLO-P13-EXPERIMENT-KEY\x00" + label.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


# One strict schema is used by authorities, replicas and offline verification.
from .decision_wire import (
    decision_to_wire as _decision_wire,
    decision_from_wire as _decision_from_wire,
    decision_digest as _decision_digest,
)


def _post_json(url: str, payload: Mapping[str, object], timeout: float) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=_canonical(payload),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"trust-anchor HTTP status {response.status}")
        result = json.loads(response.read())
    if not isinstance(result, dict):
        raise ValueError("trust-anchor response must be an object")
    return result


class _JSONHandler(BaseHTTPRequestHandler):
    server_version = "VERCLO-TrustAnchor/1.3"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 2 or size > 1_048_576:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(size))
            status, response = self.server.service.handle(self.path, payload)  # type: ignore[attr-defined]
        except Exception as exc:  # fail closed at the wire boundary
            status, response = 400, {"error": type(exc).__name__}
        body = _canonical(response)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _HTTPService:
    def __init__(self, service: object, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), _JSONHandler)
        self._server.service = service  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "_HTTPService":
        if self._thread is not None:
            raise RuntimeError("service already started")
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.02), daemon=True
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._thread = None
        if hasattr(self._server.service, "close"):
            self._server.service.close()

    def __enter__(self) -> "_HTTPService":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.close()


class SignedAuthorityService:
    """A network authority returning signed receipt-validation decisions."""

    def __init__(
        self,
        authority_id: str,
        private_key: Ed25519PrivateKey,
        decision: BackendValidation,
    ) -> None:
        self.authority_id = authority_id
        self.private_key = private_key
        self.decision = decision
        self.request_count = 0

    def handle(self, path: str, payload: Mapping[str, object]) -> tuple[int, object]:
        if path != "/v2/validate":
            return 404, {"error": "not_found"}
        commitment = str(payload["receipt_commitment"])
        request_id = str(payload["request_id"])
        if len(commitment) != 64:
            raise ValueError("invalid receipt commitment")
        signed = {
            "authority_id": self.authority_id,
            "decision": _decision_wire(self.decision),
            "receipt_commitment": commitment,
            "request_id": request_id,
        }
        self.request_count += 1
        return 200, {**signed, "signature": _b64(self.private_key.sign(_canonical(signed)))}


class NetworkSignedValidationBackend:
    name = "network-signed-authority-v2"

    def __init__(
        self,
        endpoint: str,
        authority_id: str,
        public_key: bytes,
        *,
        timeout: float = 2.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.authority_id = authority_id
        self.public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self.timeout = timeout
        self.last_cost: dict[str, int] = {}

    def validate(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> BackendValidation:
        del obligation
        commitment = PBFTValidationBackend.receipt_commitment(receipt)
        request_id = hashlib.sha256(
            (receipt.receipt_id + evaluation_time.isoformat()).encode()
        ).hexdigest()
        request = {"receipt_commitment": commitment, "request_id": request_id}
        started = time.perf_counter_ns()
        response_size = 0
        try:
            response = _post_json(
                self.endpoint + "/v2/validate", request, self.timeout
            )
            response_size = len(_canonical(response))
            signature = str(response.pop("signature"))
            if response.get("authority_id") != self.authority_id:
                raise ValueError("authority mismatch")
            if response.get("receipt_commitment") != commitment:
                raise ValueError("commitment mismatch")
            if response.get("request_id") != request_id:
                raise ValueError("request mismatch")
            self.public_key.verify(_unb64(signature), _canonical(response))
            result = _decision_from_wire(self.name, response["decision"])  # type: ignore[arg-type]
            diagnostics = result.diagnostics
        except (OSError, ValueError, TypeError, KeyError, InvalidSignature, urllib.error.URLError):
            result = BackendValidation(
                backend_name=self.name,
                verification_material_available=False,
                assumptions_valid=False,
            )
            diagnostics = ("NETWORK_SIGNED_AUTHORITY_REJECTED",)
        elapsed = time.perf_counter_ns() - started
        self.last_cost = {
            "latency_ns": elapsed,
            "messages_sent": 1,
            "request_bytes": len(_canonical(request)),
            "response_bytes": response_size,
        }
        return replace(result, diagnostics=diagnostics)


def _leaf(commitment: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(commitment)).digest()


def _parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _merkle_proof(leaves: list[bytes], index: int) -> list[dict[str, str]]:
    proof: list[dict[str, str]] = []
    level = list(leaves)
    cursor = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = cursor - 1 if cursor % 2 else cursor + 1
        proof.append({"side": "left" if cursor % 2 else "right", "hash": level[sibling].hex()})
        cursor //= 2
        level = [_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


class MerkleTransparencyService(SignedAuthorityService):
    """Append-only network log returning a signed Merkle inclusion proof."""

    def __init__(
        self,
        authority_id: str,
        private_key: Ed25519PrivateKey,
        decision: BackendValidation,
    ) -> None:
        super().__init__(authority_id, private_key, decision)
        self._commitments: list[str] = []
        self._lock = threading.Lock()

    def handle(self, path: str, payload: Mapping[str, object]) -> tuple[int, object]:
        if path != "/v2/append-and-prove":
            return 404, {"error": "not_found"}
        commitment = str(payload["receipt_commitment"])
        request_id = str(payload["request_id"])
        if len(commitment) != 64:
            raise ValueError("invalid receipt commitment")
        with self._lock:
            self._commitments.append(commitment)
            index = len(self._commitments) - 1
            leaves = [_leaf(row) for row in self._commitments]
            proof = _merkle_proof(leaves, index)
            root = _merkle_root(leaves).hex()
            tree_size = len(leaves)
        signed = {
            "authority_id": self.authority_id,
            "decision": _decision_wire(self.decision),
            "index": index,
            "proof": proof,
            "receipt_commitment": commitment,
            "request_id": request_id,
            "root": root,
            "tree_size": tree_size,
        }
        self.request_count += 1
        return 200, {**signed, "signature": _b64(self.private_key.sign(_canonical(signed)))}


class NetworkMerkleValidationBackend(NetworkSignedValidationBackend):
    name = "network-merkle-transparency-v2"

    def validate(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> BackendValidation:
        del obligation
        commitment = PBFTValidationBackend.receipt_commitment(receipt)
        request_id = hashlib.sha256(
            (receipt.receipt_id + evaluation_time.isoformat()).encode()
        ).hexdigest()
        request = {"receipt_commitment": commitment, "request_id": request_id}
        started = time.perf_counter_ns()
        response_size = 0
        try:
            response = _post_json(
                self.endpoint + "/v2/append-and-prove", request, self.timeout
            )
            response_size = len(_canonical(response))
            signature = str(response.pop("signature"))
            if response.get("authority_id") != self.authority_id:
                raise ValueError("authority mismatch")
            if response.get("receipt_commitment") != commitment:
                raise ValueError("commitment mismatch")
            if response.get("request_id") != request_id:
                raise ValueError("request mismatch")
            self.public_key.verify(_unb64(signature), _canonical(response))
            cursor = _leaf(commitment)
            for item in response["proof"]:  # type: ignore[union-attr]
                sibling = bytes.fromhex(str(item["hash"]))
                cursor = _parent(sibling, cursor) if item["side"] == "left" else _parent(cursor, sibling)
            if cursor.hex() != response["root"]:
                raise ValueError("Merkle proof mismatch")
            result = _decision_from_wire(self.name, response["decision"])
            diagnostics = result.diagnostics
        except (OSError, ValueError, TypeError, KeyError, InvalidSignature, urllib.error.URLError):
            result = BackendValidation(
                backend_name=self.name,
                verification_material_available=False,
                assumptions_valid=False,
            )
            diagnostics = ("NETWORK_MERKLE_PROOF_REJECTED",)
        self.last_cost = {
            "latency_ns": time.perf_counter_ns() - started,
            "messages_sent": 1,
            "request_bytes": len(_canonical(request)),
            "response_bytes": response_size,
        }
        return replace(result, diagnostics=diagnostics)


@dataclass(frozen=True)
class NetworkFaultProfile:
    """Transport and Byzantine behavior applied to named PBFT validators."""

    partitioned_validator_ids: tuple[str, ...] = ()
    crashed_validator_ids: tuple[str, ...] = ()
    withholding_validator_ids: tuple[str, ...] = ()
    equivocating_validator_ids: tuple[str, ...] = ()
    invalid_signature_validator_ids: tuple[str, ...] = ()
    conflicting_decision_validator_ids: tuple[str, ...] = ()


def _check_committee(keys: Mapping[str, bytes], epoch: str) -> str:
    if type(epoch) is not str or not epoch:
        raise ValueError("membership epoch is required")
    if len(keys) < 4 or (len(keys) - 1) % 3:
        raise ValueError("network PBFT requires n = 3f + 1, f >= 1")
    if len(set(keys.values())) != len(keys):
        raise ValueError("validators must have distinct public keys")
    return committee_digest(keys)


def _bind_database(connection: sqlite3.Connection, context: Mapping[str, str]) -> None:
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    if tables and "protocol_context" not in tables:
        raise ValueError("legacy PBFT state: archive it and start a fresh epoch and database")
    connection.execute("CREATE TABLE IF NOT EXISTS protocol_context (value TEXT NOT NULL)")
    expected = _canonical(dict(context)).decode()
    row = connection.execute("SELECT value FROM protocol_context").fetchone()
    if row is not None and row[0] != expected:
        raise ValueError("PBFT state context mismatch; use the matching epoch, keys and identity")
    if row is None:
        connection.execute("INSERT INTO protocol_context VALUES (?)", (expected,))


class PBFTReplicaState:
    """Atomic per-sequence view promises, prepared proofs and finalized values.

    SQLite FULL commits precede network replies. In-memory state is only for
    ephemeral experiments; it does not support crash recovery. A prepared proof
    is retained before signing COMMIT, even when no FINALIZE request arrives.
    """

    def __init__(self, path: str | Path | None, context: Mapping[str, str]) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._data: dict[str, dict] = {}
        self._connection: sqlite3.Connection | None = None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            try:
                connection.execute("BEGIN IMMEDIATE")
                _bind_database(connection, context)
                connection.execute("CREATE TABLE IF NOT EXISTS replica_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL)")
                connection.execute("INSERT OR IGNORE INTO replica_state VALUES (1, '{}')")
                connection.commit()
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                self._data = json.loads(connection.execute("SELECT value FROM replica_state WHERE singleton=1").fetchone()[0])
                self._connection = connection
            except Exception:
                connection.rollback()
                connection.close()
                raise

    @contextmanager
    def atomic(self):
        with self._lock:
            connection = self._connection
            if connection is not None:
                connection.execute("BEGIN IMMEDIATE")
                self._data = json.loads(connection.execute("SELECT value FROM replica_state WHERE singleton=1").fetchone()[0])
            before = deepcopy(self._data)
            try:
                yield
                if connection is not None:
                    connection.execute("UPDATE replica_state SET value=? WHERE singleton=1", (_canonical(self._data).decode(),))
                    connection.commit()
            except BaseException:
                self._data = before
                if connection is not None:
                    connection.rollback()
                raise

    def _row(self, sequence: int) -> dict:
        return self._data.setdefault(str(sequence), {"view": -1, "proposals": {}, "prepared": [], "committed": None})

    def advance_view(self, sequence: int, target_view: int) -> bool:
        row = self._row(sequence)
        if target_view < row["view"]:
            return False
        row["view"] = target_view
        return True

    def record_proposal(self, view: int, sequence: int, receipt: str, decision: str) -> bool:
        row = self._row(sequence)
        value = [receipt, decision]
        if row["committed"] is not None and row["committed"] != value:
            return False
        prior = row["proposals"].get(str(view))
        if prior is not None and prior != value:
            return False
        row["proposals"][str(view)] = value
        return True

    def proposal(self, view: int, sequence: int):
        return self._row(sequence)["proposals"].get(str(view))

    def prepared(self, sequence: int) -> list[dict]:
        return deepcopy(self._row(sequence)["prepared"])

    def mark_prepared(self, sequence: int, votes: list[dict]) -> None:
        row = self._row(sequence)
        old = row["prepared"]
        if not old or votes[0]["view"] >= old[0]["view"]:
            row["prepared"] = deepcopy(votes)

    def mark_committed(self, view: int, sequence: int) -> None:
        row = self._row(sequence)
        value = self.proposal(view, sequence)
        if value is None or (row["committed"] is not None and row["committed"] != value):
            raise ValueError("conflicting or unknown finalization")
        row["committed"] = value

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {"proposals": sum(len(row["proposals"]) for row in self._data.values()),
                "committed": sum(row["committed"] is not None for row in self._data.values()),
                "prepared": sum(bool(row["prepared"]) for row in self._data.values()),
                "tracked_sequences": len(self._data)}

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None


class PBFTClientState:
    """One sequence namespace per committee/epoch; preserve it across restarts."""

    def __init__(self, path: str | Path | None, context: Mapping[str, str]) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._sequence = 0
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                _bind_database(connection, context)
                connection.execute("CREATE TABLE IF NOT EXISTS client_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL)")
                connection.execute("INSERT OR IGNORE INTO client_state VALUES (1, 0)")
                connection.commit()
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")

    def next_sequence(self) -> int:
        with self._lock:
            if self.path is None:
                self._sequence += 1
                return self._sequence
            with sqlite3.connect(self.path) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                sequence = connection.execute("SELECT sequence FROM client_state WHERE singleton=1").fetchone()[0] + 1
                connection.execute("UPDATE client_state SET sequence=? WHERE singleton=1", (sequence,))
                connection.commit()
                return sequence


def _position(view: object, sequence: object) -> None:
    if type(view) is not int or view < 0 or type(sequence) is not int or sequence < 1:
        raise ValueError("invalid PBFT position")


def _digest_value(value: object) -> None:
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError("invalid commitment")


def _vote_from_wire(value: Mapping[str, object]) -> PBFTSignedVote:
    if not isinstance(value, Mapping) or set(value) != set(PBFTSignedVote.__dataclass_fields__):
        raise ValueError("unsupported PBFT vote schema")
    _position(value["view"], value["sequence"])
    for field in ("receipt_commitment", "decision_commitment", "committee_digest"):
        _digest_value(value[field])
    for field in ("validator_id", "phase", "membership_epoch", "signature"):
        if type(value[field]) is not str or not value[field]:
            raise ValueError("invalid vote field")
    return PBFTSignedVote(**value)


def _vote_wire(vote: PBFTSignedVote) -> dict[str, object]:
    return asdict(vote)


def _verify_vote(vote: PBFTSignedVote, phase: str, keys: Mapping[str, bytes], epoch: str) -> None:
    _vote_from_wire(_vote_wire(vote))
    if (vote.phase != phase or vote.validator_id not in keys
        or vote.membership_epoch != epoch or vote.committee_digest != committee_digest(keys)):
        raise ValueError("vote context or phase invalid")
    Ed25519PublicKey.from_public_bytes(keys[vote.validator_id]).verify(_unb64(vote.signature), vote.signing_bytes())


def _quorum_votes(raw: object, phase: str, keys: Mapping[str, bytes], epoch: str,
                  view: int, sequence: int, receipt: str, decision: str) -> list[PBFTSignedVote]:
    if not isinstance(raw, list):
        raise ValueError("quorum must be a list")
    votes = [_vote_from_wire(item) for item in raw]
    seen: set[str] = set()
    for vote in votes:
        _verify_vote(vote, phase, keys, epoch)
        if (vote.validator_id in seen or (vote.view, vote.sequence, vote.receipt_commitment,
                vote.decision_commitment) != (view, sequence, receipt, decision)):
            raise ValueError("quorum binding or duplicate invalid")
        seen.add(vote.validator_id)
    if len(seen) < 2 * ((len(keys) - 1) // 3) + 1:
        raise ValueError("quorum missing")
    return votes


def _view_change_bytes(value: Mapping[str, object]) -> bytes:
    return b"VERCLO-PBFT-VIEW-CHANGE-v2\x00" + _canonical(value)


def _verify_view_change(raw: object, keys: Mapping[str, bytes], epoch: str,
                        view: int, sequence: int) -> list[PBFTSignedVote]:
    fields = {"validator_id", "membership_epoch", "committee_digest", "view", "sequence", "prepared", "signature"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("invalid view-change schema")
    value = {k: v for k, v in raw.items() if k != "signature"}
    _position(raw["view"], raw["sequence"])
    if (raw["validator_id"] not in keys or raw["membership_epoch"] != epoch
        or raw["committee_digest"] != committee_digest(keys)
        or raw["view"] != view or raw["sequence"] != sequence or view < 1):
        raise ValueError("view-change context mismatch")
    Ed25519PublicKey.from_public_bytes(keys[raw["validator_id"]]).verify(
        _unb64(raw["signature"]), _view_change_bytes(value))
    prepared = raw["prepared"]
    if not isinstance(prepared, list):
        raise ValueError("invalid prepared proof")
    if not prepared:
        return []
    first = _vote_from_wire(prepared[0])
    if first.view >= view:
        raise ValueError("prepared proof must precede the new view")
    return _quorum_votes(prepared, "PREPARE", keys, epoch, first.view, sequence,
                         first.receipt_commitment, first.decision_commitment)


def _new_view_value(raw: object, keys: Mapping[str, bytes], epoch: str,
                    view: int, sequence: int) -> tuple[str, str] | None:
    if not isinstance(raw, list):
        raise ValueError("view-change proof must be a list")
    seen: set[str] = set()
    prepared: list[PBFTSignedVote] = []
    for item in raw:
        proof = _verify_view_change(item, keys, epoch, view, sequence)
        if item["validator_id"] in seen:
            raise ValueError("duplicate view-change signer")
        seen.add(item["validator_id"])
        if proof:
            prepared.append(proof[0])
    if len(seen) < 2 * ((len(keys) - 1) // 3) + 1:
        raise ValueError("view-change quorum missing")
    if not prepared:
        return None
    highest = max(vote.view for vote in prepared)
    values = {(vote.receipt_commitment, vote.decision_commitment) for vote in prepared if vote.view == highest}
    if len(values) != 1:
        raise ValueError("conflicting highest prepared proofs")
    return next(iter(values))


class PBFTValidatorService:
    """Replica enforcing safe per-sequence view changes under at most f faults."""

    def __init__(self, validator_id: str, private_key: Ed25519PrivateKey,
                 membership: Mapping[str, bytes], membership_epoch: str, decision: BackendValidation,
                 *, fault_profile: NetworkFaultProfile | None = None, state_path: str | Path | None = None) -> None:
        self.committee_digest = _check_committee(membership, membership_epoch)
        if validator_id not in membership or _public_bytes(private_key) != membership[validator_id]:
            raise ValueError("private key does not match validator membership")
        _decision_wire(decision)
        self.validator_id, self.private_key = validator_id, private_key
        self.membership, self.membership_epoch = dict(membership), membership_epoch
        self.decision = decision
        self.fault_profile = fault_profile or NetworkFaultProfile()
        self.state = PBFTReplicaState(state_path, {"protocol": "pbft-v2", "epoch": membership_epoch,
            "committee": self.committee_digest, "validator": validator_id})
        self.message_count = 0

    def close(self) -> None:
        self.state.close()

    def _sign_vote(self, phase: str, view: int, sequence: int, receipt: str, decision: str) -> PBFTSignedVote:
        vote = PBFTSignedVote(self.validator_id, phase, view, sequence, receipt, decision, "",
            self.membership_epoch, self.committee_digest)
        signature = _b64(self.private_key.sign(vote.signing_bytes()))
        if self.validator_id in self.fault_profile.invalid_signature_validator_ids:
            signature = _b64(b"\x00" * 64)
        return replace(vote, signature=signature)

    def handle(self, path: str, payload: Mapping[str, object]) -> tuple[int, object]:
        self.message_count += 1
        if (self.validator_id in self.fault_profile.crashed_validator_ids
            or self.validator_id in self.fault_profile.withholding_validator_ids):
            return 503, {"error": "unavailable"}
        if path == "/v2/status":
            return 200, {"validator_id": self.validator_id, "membership_epoch": self.membership_epoch,
                "committee_digest": self.committee_digest, "protocol": "pbft-v2",
                "storage": "sqlite-full" if self.state.path else "ephemeral-memory",
                "state": self.state.summary()}
        if path not in {"/v2/view-change", "/v2/propose", "/v2/preprepare", "/v2/commit", "/v2/finalize"}:
            return 404, {"error": "unsupported_protocol_endpoint"}
        # Atomicity closes a race between promising a new view and signing an
        # old-view COMMIT. SQLite commit completes before this reply escapes.
        with self.state.atomic():
            return self._handle(path, payload)

    def _handle(self, path: str, payload: Mapping[str, object]) -> tuple[int, object]:
        view, sequence = payload["view"], payload["sequence"]
        _position(view, sequence)
        if (payload.get("membership_epoch") != self.membership_epoch
            or payload.get("committee_digest") != self.committee_digest):
            raise ValueError("membership context mismatch")
        if not self.state.advance_view(sequence, view):
            return 409, {"error": "view_regression"}
        if path == "/v2/view-change":
            if view < 1:
                raise ValueError("view must advance")
            prepared = self.state.prepared(sequence)
            if prepared and prepared[0]["view"] >= view:
                raise ValueError("cannot omit a prepared proof from the current view")
            value = {"validator_id": self.validator_id, "membership_epoch": self.membership_epoch,
                "committee_digest": self.committee_digest, "view": view, "sequence": sequence,
                "prepared": prepared}
            return 200, {**value, "signature": _b64(self.private_key.sign(_view_change_bytes(value)))}
        receipt, decision = payload["receipt_commitment"], payload["decision_commitment"]
        _digest_value(receipt)
        if decision != _decision_digest(_decision_wire(self.decision)):
            raise ValueError("decision commitment not admitted")
        leader = sorted(self.membership)[view % len(self.membership)]
        if path in {"/v2/propose", "/v2/preprepare"}:
            if view:
                selected = _new_view_value(payload.get("view_change_votes"), self.membership,
                    self.membership_epoch, view, sequence)
                if selected is not None and selected != (receipt, decision):
                    raise ValueError("proposal conflicts with highest prepared value")
            if path == "/v2/propose":
                if self.validator_id != leader:
                    return 409, {"error": "not_view_leader"}
                phase = "PRE-PREPARE"
            else:
                vote = _vote_from_wire(payload["leader_vote"])
                _verify_vote(vote, "PRE-PREPARE", self.membership, self.membership_epoch)
                if (vote.validator_id, vote.view, vote.sequence, vote.receipt_commitment,
                    vote.decision_commitment) != (leader, view, sequence, receipt, decision):
                    raise ValueError("leader proposal binding invalid")
                phase = "PREPARE"
            if not self.state.record_proposal(view, sequence, receipt, decision):
                return 409, {"error": "conflicting_proposal"}
            if phase == "PREPARE" and self.validator_id in self.fault_profile.equivocating_validator_ids:
                receipt = "0" * 64
            return 200, _vote_wire(self._sign_vote(phase, view, sequence, receipt, decision))
        if self.state.proposal(view, sequence) != [receipt, decision]:
            raise ValueError("proposal missing")
        if path == "/v2/commit":
            _quorum_votes(payload["prepare_votes"], "PREPARE", self.membership,
                self.membership_epoch, view, sequence, receipt, decision)
            self.state.mark_prepared(sequence, payload["prepare_votes"])
            if self.validator_id in self.fault_profile.equivocating_validator_ids:
                receipt = "f" * 64
            if self.validator_id in self.fault_profile.conflicting_decision_validator_ids:
                decision = "e" * 64
            return 200, _vote_wire(self._sign_vote("COMMIT", view, sequence, receipt, decision))
        _quorum_votes(payload["commit_votes"], "COMMIT", self.membership,
            self.membership_epoch, view, sequence, receipt, decision)
        # An honest finalizer must itself have prepared (and persisted that
        # proof). Otherwise it cannot carry the finalized value into a new view.
        prepared = self.state.prepared(sequence)
        if not prepared or (prepared[0]["view"], prepared[0]["receipt_commitment"], prepared[0]["decision_commitment"]) != (view, receipt, decision):
            raise ValueError("local prepared proof missing")
        self.state.mark_committed(view, sequence)
        return 200, {"finalized": True, "validator_id": self.validator_id,
            "finalize_vote": _vote_wire(self._sign_vote("FINALIZE", view, sequence, receipt, decision))}


class NetworkPBFTClient:
    """Forms context-bound certificates and retains per-thread operation evidence.

    The client coordinates one sequence namespace. Multiple processes must share
    its durable allocator. If a new view selects another receipt already in that
    sequence, this call fails closed rather than reporting that receipt as ours.
    """

    def __init__(self, endpoints: Mapping[str, str], public_keys: Mapping[str, bytes],
                 membership_epoch: str, decision: BackendValidation, *,
                 fault_profile: NetworkFaultProfile | None = None, timeout: float = 1.0,
                 state_path: str | Path | None = None, max_view_changes: int | None = None,
                 delivery_strategy: str = "serial") -> None:
        if set(endpoints) != set(public_keys):
            raise ValueError("PBFT endpoints and keys must name the same validators")
        self.committee_digest = _check_committee(public_keys, membership_epoch)
        _decision_wire(decision)
        self.endpoints, self.public_keys = dict(endpoints), dict(public_keys)
        self.membership_epoch, self.decision = membership_epoch, decision
        self.fault_profile = fault_profile or NetworkFaultProfile()
        referenced = {v for values in asdict(self.fault_profile).values() for v in values}
        if referenced - set(endpoints):
            raise ValueError("fault profile references unknown validators")
        self.timeout = timeout
        self.state = PBFTClientState(state_path, {"protocol": "pbft-v2-client", "epoch": membership_epoch,
            "committee": self.committee_digest})
        self.max_view_changes = len(endpoints) - 1 if max_view_changes is None else max_view_changes
        if type(self.max_view_changes) is not int or self.max_view_changes < 0:
            raise ValueError("max_view_changes must be a non-negative integer")
        if delivery_strategy not in {"serial", "parallel_all", "certificate_frontier"}:
            raise ValueError("unknown PBFT delivery strategy")
        self.delivery_strategy = delivery_strategy
        self._latencies = {}
        self._latency_lock = threading.Lock()
        self._local = threading.local()

    @property
    def last_cost(self) -> dict[str, int]:
        return getattr(self._local, "cost", {})

    @last_cost.setter
    def last_cost(self, value: dict[str, int]) -> None:
        self._local.cost = value

    @property
    def last_certificate(self) -> PBFTValidationCertificate | None:
        return getattr(self._local, "certificate", None)

    def _send(self, validator_id: str, path: str, payload: Mapping[str, object]) -> dict[str, object] | None:
        if validator_id in self.fault_profile.partitioned_validator_ids:
            return None
        try:
            return _post_json(self.endpoints[validator_id] + path, payload, self.timeout)
        except (OSError, ValueError, TypeError, urllib.error.URLError):
            return None

    def _valid_vote(self, vote: PBFTSignedVote, phase: str, view: int, sequence: int,
                    receipt_commitment: str, decision_commitment: str) -> bool:
        try:
            _verify_vote(vote, phase, self.public_keys, self.membership_epoch)
            return (vote.view, vote.sequence, vote.receipt_commitment, vote.decision_commitment) == (
                view, sequence, receipt_commitment, decision_commitment)
        except (InvalidSignature, ValueError, TypeError, KeyError):
            return False

    def validate_receipt(self, receipt: CustodianReceipt, obligation: Obligation,
                         evaluation_time: datetime) -> PBFTValidationCertificate:
        del obligation, evaluation_time
        self._local.certificate = None
        self.last_cost = {}
        started = time.perf_counter_ns()
        sequence = self.state.next_sequence()
        ids = tuple(sorted(self.endpoints))
        receipt_commitment = PBFTValidationBackend.receipt_commitment(receipt)
        decision_commitment = _decision_digest(_decision_wire(self.decision))
        quorum = 2 * ((len(ids) - 1) // 3) + 1
        cost = {"sequence": sequence, "messages_sent": 0, "request_bytes": 0, "response_bytes": 0,
            "prepare_votes": 0, "commit_votes": 0, "view": 0, "view_changes": 0,
            "view_change_votes": 0, "finalized_acks": 0}

        cost_lock = threading.Lock()
        operation_latencies = {}
        prepared_nodes = set(ids)
        committed_nodes = set()
        prepare_request = None

        def send(validator_id, path, request):
            start = time.perf_counter_ns()
            with cost_lock:
                cost["messages_sent"] += 1
                cost["request_bytes"] += len(_canonical(request))
            response = self._send(validator_id, path, request)
            elapsed = time.perf_counter_ns() - start
            with cost_lock:
                operation_latencies[(validator_id, path)] = elapsed
                if response is not None:
                    cost["response_bytes"] += len(_canonical(response))
            return response

        def gather(path, request, phase):
            # Scheduling changes delivery only: quorum sizes, signed contexts,
            # phases, prepared proofs and finalization checks remain unchanged.
            unique = {}
            frontier = self.delivery_strategy == "certificate_frontier" and phase in {"COMMIT", "FINALIZE"}
            with self._latency_lock:
                estimates = dict(self._latencies)
            candidates = list(prepared_nodes if frontier else ids)
            candidates.sort(key=lambda node: (
                int(phase == "FINALIZE" and node not in committed_nodes),
                estimates.get(node, 0), node))

            def exchange(node):
                if frontier and phase == "FINALIZE" and node not in committed_nodes:
                    # A fallback finalizer must first persist the prepared
                    # certificate. Merely receiving PRE-PREPARE is insufficient.
                    catchup = send(node, "/v2/commit", prepare_request)
                    try:
                        vote = _vote_from_wire(catchup)
                        if not self._valid_vote(vote, "COMMIT", view, sequence, receipt_commitment, decision_commitment):
                            return None
                    except (ValueError, KeyError, TypeError):
                        return None
                    with cost_lock:
                        cost["catchup_commits"] = cost.get("catchup_commits", 0) + 1
                return send(node, path, request)

            while candidates:
                count = max(1, quorum - len(unique)) if frontier else len(candidates)
                wave, candidates = candidates[:count], candidates[count:]
                if self.delivery_strategy == "serial":
                    responses = [exchange(node) for node in wave]
                else:
                    # All submitted work is drained before returning; no
                    # background network cost is hidden from measured latency.
                    with ThreadPoolExecutor(max_workers=min(32, len(wave))) as executor:
                        responses = list(executor.map(exchange, wave))
                for node, response in zip(wave, responses):
                    if response is None:
                        continue
                    try:
                        vote = _vote_from_wire(response["finalize_vote"] if phase == "FINALIZE" else response)
                        if self._valid_vote(vote, phase, view, sequence, receipt_commitment, decision_commitment):
                            unique[vote.validator_id] = vote
                            with self._latency_lock:
                                elapsed = operation_latencies.get((node, path), 0)
                                prior = self._latencies.get(node, elapsed)
                                self._latencies[node] = (3 * prior + elapsed) // 4
                    except (ValueError, KeyError, TypeError):
                        continue
                if not frontier or len(unique) >= quorum:
                    break
            return tuple(unique.values())

        commits: tuple[PBFTSignedVote, ...] = ()
        finalizes: tuple[PBFTSignedVote, ...] = ()
        for view in range(self.max_view_changes + 1):
            commits, finalizes = (), ()
            prepared_nodes, committed_nodes = set(ids), set()
            cost.update(view=view, view_changes=view, prepare_votes=0, commit_votes=0, finalized_acks=0)
            core = {"decision_commitment": decision_commitment, "receipt_commitment": receipt_commitment,
                "membership_epoch": self.membership_epoch, "committee_digest": self.committee_digest,
                "sequence": sequence, "view": view}
            changes = []
            if view:
                for validator_id in ids:
                    response = send(validator_id, "/v2/view-change", core)
                    try:
                        _verify_view_change(response, self.public_keys, self.membership_epoch, view, sequence)
                        changes.append(response)
                    except (ValueError, KeyError, TypeError, InvalidSignature):
                        continue
                changes = list({row["validator_id"]: row for row in changes}.values())
                try:
                    selected = _new_view_value(changes, self.public_keys, self.membership_epoch, view, sequence)
                    if selected is not None and selected != (receipt_commitment, decision_commitment):
                        break
                except (ValueError, KeyError, TypeError, InvalidSignature):
                    continue
                cost["view_change_votes"] = len(changes)
            proposal = {**core, "view_change_votes": changes}
            leader_id = ids[view % len(ids)]
            response = send(leader_id, "/v2/propose", proposal)
            try:
                leader_vote = _vote_from_wire(response)
                if leader_vote.validator_id != leader_id or not self._valid_vote(
                    leader_vote, "PRE-PREPARE", view, sequence, receipt_commitment, decision_commitment):
                    continue
            except (ValueError, KeyError, TypeError):
                continue
            prepares = gather("/v2/preprepare", {**proposal, "leader_vote": _vote_wire(leader_vote)}, "PREPARE")
            cost["prepare_votes"] = len(prepares)
            if len(prepares) < quorum:
                continue
            prepared_nodes = {v.validator_id for v in prepares}
            prepare_request = {**core, "prepare_votes": [_vote_wire(v) for v in prepares]}
            commits = gather("/v2/commit", prepare_request, "COMMIT")
            committed_nodes = {v.validator_id for v in commits}
            cost["commit_votes"] = len(commits)
            if len(commits) < quorum:
                continue
            finalizes = gather("/v2/finalize", {**core, "commit_votes": [_vote_wire(v) for v in commits]}, "FINALIZE")
            cost["finalized_acks"] = len(finalizes)
            if len(finalizes) >= quorum:
                break
        cost["latency_ns"] = time.perf_counter_ns() - started
        self.last_cost = cost
        decision_fields = {key: getattr(self.decision, key) for key in (
            "verification_material_available", "authenticator_valid", "credential_valid_at_event",
            "anchor_valid", "ordering_support_valid", "mechanism_present", "mechanism_valid",
            "mechanism_expires_at", "assumptions_valid", "diagnostics")}
        certificate = PBFTValidationCertificate(receipt_commitment=receipt_commitment, validator_ids=ids,
            approving_validator_ids=tuple(v.validator_id for v in commits), **decision_fields,
            view=cost["view"], sequence=sequence, membership_epoch=self.membership_epoch,
            signed_commit_votes=commits, signed_finalize_votes=finalizes)
        self._local.certificate = certificate
        return certificate


class NetworkPBFTCluster:
    """Lifecycle manager for local PBFT services, including restart studies."""

    def __init__(
        self,
        validator_ids: tuple[str, ...],
        decision: BackendValidation,
        *,
        membership_epoch: str = "P13-EPOCH-1",
        fault_profile: NetworkFaultProfile | None = None,
        persistent_root: str | Path | None = None,
        bind_host: str = "127.0.0.1",
    ) -> None:
        if len(set(validator_ids)) != len(validator_ids):
            raise ValueError("validator identifiers must be unique")
        self.private_keys = {
            row: deterministic_private_key("pbft:" + row) for row in validator_ids
        }
        membership = {row: _public_bytes(key) for row, key in self.private_keys.items()}
        self.persistent_root = (
            Path(persistent_root) if persistent_root is not None else None
        )
        if self.persistent_root is not None:
            self.persistent_root.mkdir(parents=True, exist_ok=True)
        self.services = {
            row: _HTTPService(
                PBFTValidatorService(
                    row,
                    self.private_keys[row],
                    membership,
                    membership_epoch,
                    decision,
                    fault_profile=fault_profile,
                    state_path=(
                        self.persistent_root / f"{row}.sqlite3"
                        if self.persistent_root is not None
                        else None
                    ),
                ),
                host=bind_host,
            )
            for row in validator_ids
        }
        self.membership_epoch = membership_epoch
        self.decision = decision
        self.fault_profile = fault_profile or NetworkFaultProfile()

    def start(self) -> "NetworkPBFTCluster":
        started: list[_HTTPService] = []
        try:
            for service in self.services.values():
                service.start()
                started.append(service)
        except Exception:
            for service in reversed(started):
                service.close()
            raise
        return self

    def close(self) -> None:
        for service in self.services.values():
            service.close()

    def client(self, *, timeout: float = 1.0, delivery_strategy: str = "serial") -> NetworkPBFTClient:
        return NetworkPBFTClient(
            {row: service.url for row, service in self.services.items()},
            {row: _public_bytes(key) for row, key in self.private_keys.items()},
            self.membership_epoch,
            self.decision,
            delivery_strategy=delivery_strategy,
            fault_profile=self.fault_profile,
            timeout=timeout,
            state_path=(
                self.persistent_root / "client.sqlite3"
                if self.persistent_root is not None
                else None
            ),
        )

    def backend(self, *, timeout: float = 1.0, delivery_strategy: str = "serial") -> PBFTValidationBackend:
        client = self.client(timeout=timeout, delivery_strategy=delivery_strategy)
        return PBFTValidationBackend(
            client,
            validator_count=len(self.services),
            fault_tolerance=(len(self.services) - 1) // 3,
            validator_public_keys=client.public_keys,
            membership_epoch=self.membership_epoch,
            require_signed_votes=True,
        )

    def __enter__(self) -> "NetworkPBFTCluster":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.close()


def serve_signed_authority(
    authority_id: str,
    decision: BackendValidation,
    *,
    key: Ed25519PrivateKey | None = None,
) -> tuple[_HTTPService, bytes]:
    private_key = key or deterministic_private_key("authority:" + authority_id)
    return _HTTPService(SignedAuthorityService(authority_id, private_key, decision)), _public_bytes(private_key)


def serve_merkle_authority(
    authority_id: str,
    decision: BackendValidation,
    *,
    key: Ed25519PrivateKey | None = None,
) -> tuple[_HTTPService, bytes]:
    private_key = key or deterministic_private_key("merkle:" + authority_id)
    return _HTTPService(MerkleTransparencyService(authority_id, private_key, decision)), _public_bytes(private_key)


def serve_pbft_validator(
    validator_id: str,
    private_key: Ed25519PrivateKey,
    membership: Mapping[str, bytes],
    membership_epoch: str,
    decision: BackendValidation,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    state_path: str | Path | None = None,
    fault_profile: NetworkFaultProfile | None = None,
) -> _HTTPService:
    """Create one independently deployable PBFT validator HTTP service."""

    if validator_id not in membership:
        raise ValueError("validator is absent from membership")
    if _public_bytes(private_key) != membership[validator_id]:
        raise ValueError("private key does not match membership")
    return _HTTPService(
        PBFTValidatorService(
            validator_id,
            private_key,
            membership,
            membership_epoch,
            decision,
            fault_profile=fault_profile,
            state_path=state_path,
        ),
        host=host,
        port=port,
    )
