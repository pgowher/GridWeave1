"""Deterministic atomic writer for evaluator-only detached evidence fixtures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from htgl_dataset_generator.evidence import EvidenceReceiptBuild


@dataclass(frozen=True)
class EvidenceFixtureWriteResult:
    root: Path
    manifest_path: Path
    manifest_sha256: str
    files: Mapping[str, Path]


def write_evidence_fixture_bundle(
    build: EvidenceReceiptBuild,
    output_dir: str | os.PathLike[str],
) -> EvidenceFixtureWriteResult:
    """Write detached payloads and evaluator truth without exposing secret key bytes."""

    root = Path(output_dir) / "evidence_fixtures"
    payload_root = root / "payloads"
    payload_root.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}
    fixture_by_id = {item.receipt_id: item for item in build.receipt_fixtures}
    if len(fixture_by_id) != len(build.receipt_fixtures):
        raise ValueError("duplicate receipt fixture IDs")
    if set(fixture_by_id) != {str(row["receipt_id"]) for row in build.evidence_receipts}:
        raise ValueError("detached payload fixtures must match emitted evidence receipts exactly")
    for receipt_id in sorted(fixture_by_id):
        try:
            payload = bytes.fromhex(fixture_by_id[receipt_id].canonical_payload_hex)
        except ValueError as exc:
            raise ValueError(f"fixture {receipt_id}: canonical_payload_hex is invalid") from exc
        relative = f"payloads/{receipt_id}.bin"
        path = root / relative
        _atomic_write(path, payload)
        files[relative] = path

    sidecars = {
        "receipt_fixtures.json": [asdict(item) for item in build.receipt_fixtures],
        "synthetic_keys.json": [asdict(item) for item in build.synthetic_keys],
        "synthetic_anchors.json": [asdict(item) for item in build.synthetic_anchors],
        "adversarial_cases.json": [asdict(item) for item in build.adversarial_cases],
        "receipt_verification_truth.json": [asdict(item) for item in build.verification.truth],
        "evidence_sufficiency_truth.json": [asdict(item) for item in build.verification.sufficiency.truth],
    }
    forbidden_key_fields = {"secret", "private_key", "private_key_hex", "hmac_key", "hmac_key_hex"}
    observed_key_fields = set(sidecars["synthetic_keys.json"][0]) if sidecars["synthetic_keys.json"] else set()
    if forbidden_key_fields & observed_key_fields:
        raise ValueError("synthetic key sidecar exposes forbidden secret material")
    for relative, value in sorted(sidecars.items()):
        path = root / relative
        _atomic_write(path, _canonical_json_bytes(value))
        files[relative] = path

    file_entries = [
        {
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for relative, path in sorted(files.items())
    ]
    manifest = {
        "format": "htgl.evidence.detached-fixture-bundle.v1",
        "privacy_class": "evaluator_only",
        "authoritative_dataset_table": False,
        "receipt_profile_bundle_sha256": build.receipt_profile_bundle_sha256,
        "proof_limit_statement": build.proof_limit_statement,
        "files": file_entries,
    }
    manifest_path = root / "fixture_manifest.json"
    manifest_bytes = _canonical_json_bytes(manifest)
    _atomic_write(manifest_path, manifest_bytes)
    return EvidenceFixtureWriteResult(
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        files=dict(sorted(files.items())),
    )
def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
from htgl_dataset_generator._atomic import atomic_replace
