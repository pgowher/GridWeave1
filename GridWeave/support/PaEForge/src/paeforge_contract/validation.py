"""Schema, leakage, identity, seed, sequence, and commitment validation."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import domain_digest, sha256_digest
from .leakage import LeakageError as LeakageError, scan_for_leakage


CONTRACT_VERSION = "1.0.0"
MODEL_VERSION = "PAE-FECM-v1.0.0"
SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas"
INPUT_SCHEMA_IDS = frozenset(
    {
        "https://paeforge.local/schema/case-manifest/v1",
        "https://paeforge.local/schema/observer-projection/v1",
        "https://paeforge.local/schema/receipt-stream/v1",
    }
)


class ContractError(ValueError):
    """Raised when individually valid documents do not form a valid exchange."""


def _schema_index() -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(payload)
        result[str(payload["$id"])] = payload
    return result


SCHEMAS = _schema_index()


def validate_document(document: Mapping[str, Any]) -> None:
    """Validate one versioned PaEForge document by its declared schema ID."""

    schema_id = document.get("schema_id")
    if schema_id not in SCHEMAS:
        raise ContractError(f"unknown or missing schema_id: {schema_id!r}")
    Draft202012Validator(
        SCHEMAS[str(schema_id)], format_checker=FormatChecker()
    ).validate(document)


def validate_verifier_input(
    document: Mapping[str, Any], *, canary_values: Iterable[str] = ()
) -> None:
    """Apply the leakage boundary before accepting any VERCLO input document."""

    scan_for_leakage(document, canary_values=canary_values)
    if document.get("schema_id") not in INPUT_SCHEMA_IDS:
        raise ContractError("document type is not admitted at the VERCLO input boundary")
    validate_document(document)


def _same(label: str, documents: tuple[Mapping[str, Any], ...]) -> None:
    values = {json.dumps(document[label], sort_keys=True) for document in documents}
    if len(values) != 1:
        raise ContractError(f"bundle {label} values do not match")


def validate_verifier_bundle(
    manifest: Mapping[str, Any],
    observer_projection: Mapping[str, Any],
    receipt_stream: Mapping[str, Any],
    *,
    canary_values: Iterable[str] = (),
) -> None:
    """Validate the three-file VERCLO input bundle and all cross-file bindings."""

    documents = (manifest, observer_projection, receipt_stream)
    canaries = tuple(canary_values)
    for document in documents:
        validate_verifier_input(document, canary_values=canaries)
    for label in ("contract_version", "model_version", "exchange_id", "run_id", "scenario_id", "case_id"):
        _same(label, documents)
    if manifest["seed"]["replicate_id"] != observer_projection["seed"]["replicate_id"]:
        raise ContractError("bundle replicate_id values do not match")
    if manifest["seed"]["replicate_id"] != receipt_stream["seed"]["replicate_id"]:
        raise ContractError("bundle replicate_id values do not match")
    if manifest["seed"]["seed_stream_digest"] != observer_projection["seed"]["seed_stream_digest"]:
        raise ContractError("bundle seed_stream_digest values do not match")
    if manifest["seed"]["seed_stream_digest"] != receipt_stream["seed"]["seed_stream_digest"]:
        raise ContractError("bundle seed_stream_digest values do not match")
    if manifest["policy"] != observer_projection["policy"]:
        raise ContractError("manifest and observer policy bindings do not match")

    observer_ref = manifest["artifacts"]["observer_projection"]
    receipt_ref = manifest["artifacts"]["receipt_stream"]
    if observer_ref["path"] != "observer-projection.json":
        raise ContractError("observer projection must use the fixed boundary filename")
    if receipt_ref["path"] != "receipt-stream.json":
        raise ContractError("receipt stream must use the fixed boundary filename")
    if observer_ref["schema_id"] != observer_projection["schema_id"]:
        raise ContractError("observer projection schema binding does not match")
    if receipt_ref["schema_id"] != receipt_stream["schema_id"]:
        raise ContractError("receipt stream schema binding does not match")
    if observer_ref["sha256"] != sha256_digest(observer_projection):
        raise ContractError("observer projection digest does not match manifest")
    if receipt_ref["sha256"] != sha256_digest(receipt_stream):
        raise ContractError("receipt stream digest does not match manifest")

    expected_projection = domain_digest(
        "paeforge-observer-projection-v1",
        {
            "observer": observer_projection["observer"],
            "policy": observer_projection["policy"],
            "case": observer_projection["case"],
            "topology": observer_projection["topology"],
            "exceptions": observer_projection["exceptions"],
            "challenges": observer_projection["challenges"],
        },
    )
    if observer_projection["projection_commitment"] != expected_projection:
        raise ContractError("observer projection semantic commitment does not match")
    receipts = receipt_stream["receipts"]
    sequences = [row["sequence"] for row in receipts]
    if sequences != list(range(len(receipts))):
        raise ContractError("receipt sequence must be contiguous, unique, and zero-based")
    receipt_ids = [row["receipt_id"] for row in receipts]
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ContractError("receipt identifiers must be unique within a stream")
    if any(row["case_id"] != manifest["case_id"] for row in receipts):
        raise ContractError("receipt case_id does not match bundle case_id")
    expected_stream = domain_digest("paeforge-receipt-stream-v1", receipts)
    if receipt_stream["stream_commitment"] != expected_stream:
        raise ContractError("receipt stream semantic commitment does not match")
