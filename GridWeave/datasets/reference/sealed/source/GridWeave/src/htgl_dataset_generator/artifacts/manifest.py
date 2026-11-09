"""Final-byte S15 inventories, manifest closure, and integrity verification."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from htgl_dataset_generator.io import write_parquet_table
from htgl_dataset_generator.schemas import ContractSpec, validate_record
from htgl_dataset_generator.seeds import content_id

from .canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
    read_parquet_metadata,
    sha256_hex,
)
from .models import ArtifactIntegrityError, StoredArtifact


ARTIFACT_MANIFEST_PATH = "artifact_manifest.parquet"
ROOT_MANIFEST_PATH = "manifest.json"
CONTROL_EXCLUSIONS = frozenset({ARTIFACT_MANIFEST_PATH, ROOT_MANIFEST_PATH})


def inventory_release_payloads(
    root: Path,
    *,
    contract: ContractSpec,
    metadata_overrides: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[StoredArtifact, ...]:
    """Inventory every staged release payload except the two manifest controls."""

    overrides = metadata_overrides or {}
    artifacts: list[StoredArtifact] = []
    table_by_schema = {table.schema_id: table for table in contract.tables}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in CONTROL_EXCLUSIONS or path.name.endswith(".tmp"):
            continue
        override = dict(overrides.get(relative, {}))
        media_type = _media_type(path)
        schema_id: str | None = None
        schema_fingerprint: str | None = None
        record_count: int | None
        uncompressed_bytes: int | None
        if media_type == "application/parquet":
            schema_id, schema_fingerprint, record_count, uncompressed_bytes = read_parquet_metadata(path)
            table = table_by_schema.get(schema_id)
            privacy_class = (
                table.privacy_class if table is not None else str(override.get("privacy_class", ""))
            )
            if not privacy_class:
                privacy_class = _custom_parquet_privacy(path)
        else:
            record_count = _record_count(path, media_type)
            uncompressed_bytes = path.stat().st_size
            privacy_class = str(override.get("privacy_class", _path_privacy(relative)))
        if privacy_class not in contract.dictionary_values("privacy_class"):
            raise ArtifactIntegrityError(
                f"artifact {relative} has uncontrolled privacy_class={privacy_class!r}"
            )
        payload = path.read_bytes()
        partition_keys = tuple(
            part.split("=", 1)[0]
            for part in PurePosixPath(relative).parts
            if "=" in part
        )
        artifacts.append(
            StoredArtifact(
                relative_path=relative,
                media_type=media_type,
                schema_id=schema_id,
                schema_fingerprint=schema_fingerprint,
                record_count=record_count,
                uncompressed_bytes=uncompressed_bytes,
                stored_bytes=len(payload),
                sha256=sha256_hex(payload),
                partition_keys=partition_keys,
                privacy_class=privacy_class,
                generation_stage=str(override.get("generation_stage", _generation_stage(relative))),
                publication_eligible=bool(
                    override.get("publication_eligible", privacy_class == "public")
                ),
            )
        )
    paths = [artifact.relative_path for artifact in artifacts]
    if len(paths) != len(set(paths)):
        raise ArtifactIntegrityError("release inventory contains duplicate relative paths")
    return tuple(sorted(artifacts, key=lambda item: item.relative_path))


def manifest_rows(
    artifacts: Iterable[StoredArtifact],
    *,
    run_id: str,
    contract: ContractSpec,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for artifact in sorted(artifacts, key=lambda item: item.relative_path):
        row = {
            "artifact_id": content_id(
                "artifact_manifest",
                {
                    "run_id": run_id,
                    "relative_path": artifact.relative_path,
                    "sha256": artifact.sha256,
                },
            ),
            "run_id": run_id,
            "relative_path": artifact.relative_path,
            "media_type": artifact.media_type,
            "schema_id": artifact.schema_id,
            "record_count": artifact.record_count,
            "uncompressed_bytes": artifact.uncompressed_bytes,
            "stored_bytes": artifact.stored_bytes,
            "sha256": artifact.sha256,
            "partition_keys": list(artifact.partition_keys),
            "privacy_class": artifact.privacy_class,
            "generation_stage": artifact.generation_stage,
            "publication_eligible": artifact.publication_eligible,
        }
        validate_record(contract, "artifact_manifest", row)
        rows.append(row)
    return tuple(rows)


def write_manifest_controls(
    root: Path,
    *,
    artifacts: tuple[StoredArtifact, ...],
    rows: tuple[dict[str, Any], ...],
    run_id: str,
    config_sha256: str,
    contract: ContractSpec,
    stable_release_timestamp: str,
    semantic_digest: str,
    bundle_set_id: str | None = None,
    bundle_access_class: str = "public",
) -> tuple[Path, Path, str, str]:
    """Write both manifests and return paths plus root and byte-set digests."""

    artifact_manifest_path = root / ARTIFACT_MANIFEST_PATH
    write_parquet_table(
        "artifact_manifest",
        rows,
        artifact_manifest_path,
        contract=contract,
        compression="ZSTD",
        compression_level=9,
        canonical_sort=True,
    )
    artifact_manifest_payload = artifact_manifest_path.read_bytes()
    artifact_manifest_entry = {
        "relative_path": ARTIFACT_MANIFEST_PATH,
        "media_type": "application/parquet",
        "schema_id": contract.table("artifact_manifest").schema_id,
        "schema_fingerprint": contract.table("artifact_manifest").schema_fingerprint,
        "record_count": len(rows),
        "stored_bytes": len(artifact_manifest_payload),
        "sha256": sha256_hex(artifact_manifest_payload),
        "privacy_class": bundle_access_class,
        "generation_stage": "S15_manifest_compiler",
    }
    entries = [
        {
            "relative_path": item.relative_path,
            "media_type": item.media_type,
            "schema_id": item.schema_id,
            "schema_fingerprint": item.schema_fingerprint,
            "record_count": item.record_count,
            "stored_bytes": item.stored_bytes,
            "sha256": item.sha256,
            "privacy_class": item.privacy_class,
            "generation_stage": item.generation_stage,
        }
        for item in artifacts
    ]
    entries.append(artifact_manifest_entry)
    entries.sort(key=lambda item: str(item["relative_path"]))
    release_byte_digest = domain_sha256(
        "release-byte-inventory-v1",
        [(item["relative_path"], item["sha256"]) for item in entries],
    )
    root_manifest = {
        "format": "htgl.dataset-generator.root-manifest.v1",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "contract_id": contract.contract_id,
        "contract_version": contract.contract_version,
        "contract_fingerprint": contract.contract_fingerprint,
        "bundle_set_id": bundle_set_id,
        "bundle_access_class": bundle_access_class,
        "stable_release_timestamp": stable_release_timestamp,
        "authoritative_storage": "typed_arrow_parquet_zstd",
        "jsonl_authority": False,
        "manifest_policy": "final_bytes_sha256_schema_bound",
        "manifest_self_reference_policy": {
            "artifact_manifest_parquet_excludes": [
                ARTIFACT_MANIFEST_PATH,
                ROOT_MANIFEST_PATH,
            ],
            "root_manifest_excludes": [ROOT_MANIFEST_PATH],
            "reason": "cryptographic digests cannot include the bytes that contain their own digest",
        },
        "artifact_manifest_sha256": artifact_manifest_entry["sha256"],
        "release_semantic_digest": semantic_digest,
        "release_byte_digest": release_byte_digest,
        "artifact_count_excluding_root_manifest": len(entries),
        "total_stored_bytes_excluding_root_manifest": sum(int(item["stored_bytes"]) for item in entries),
        "artifacts": entries,
        "claim_boundary": (
            "This release contains generated benchmark artifacts and optional replay workloads only; "
            "it does not establish legal compliance, physical deletion, HTGL execution, ledger anchoring, "
            "utility deployment, or materialization of represented population."
        ),
    }
    manifest_path = root / ROOT_MANIFEST_PATH
    payload = canonical_json_bytes(root_manifest)
    atomic_write_bytes(manifest_path, payload)
    verify_manifest_closure(root, rows=rows, contract=contract)
    return (
        artifact_manifest_path,
        manifest_path,
        sha256_hex(payload),
        release_byte_digest,
    )


def verify_manifest_closure(
    root: Path,
    *,
    rows: Iterable[Mapping[str, Any]],
    contract: ContractSpec,
) -> None:
    """Fail closed unless both manifest levels cover their declared final bytes exactly."""

    row_tuple = tuple(dict(row) for row in rows)
    row_paths = {str(row["relative_path"]) for row in row_tuple}
    payload_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in CONTROL_EXCLUSIONS
    }
    if row_paths != payload_paths:
        raise ArtifactIntegrityError(
            f"artifact_manifest payload closure mismatch missing={sorted(payload_paths-row_paths)} extra={sorted(row_paths-payload_paths)}"
        )
    for row in row_tuple:
        validate_record(contract, "artifact_manifest", row)
        path = root / str(row["relative_path"])
        payload = path.read_bytes()
        if sha256_hex(payload) != str(row["sha256"]):
            raise ArtifactIntegrityError(f"artifact manifest digest mismatch for {row['relative_path']}")
        if len(payload) != int(row["stored_bytes"]):
            raise ArtifactIntegrityError(f"artifact manifest byte count mismatch for {row['relative_path']}")
    root_manifest = json.loads((root / ROOT_MANIFEST_PATH).read_text(encoding="utf-8"))
    root_entries = root_manifest.get("artifacts")
    if not isinstance(root_entries, list):
        raise ArtifactIntegrityError("root manifest artifacts must be an array")
    root_paths = {str(item["relative_path"]) for item in root_entries}
    expected_root_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() != ROOT_MANIFEST_PATH
    }
    if root_paths != expected_root_paths or len(root_paths) != len(root_entries):
        raise ArtifactIntegrityError(
            f"root manifest closure mismatch missing={sorted(expected_root_paths-root_paths)} extra={sorted(root_paths-expected_root_paths)}"
        )
    for item in root_entries:
        path = root / str(item["relative_path"])
        payload = path.read_bytes()
        if sha256_hex(payload) != str(item["sha256"]):
            raise ArtifactIntegrityError(f"root manifest digest mismatch for {item['relative_path']}")
    expected_byte_digest = domain_sha256(
        "release-byte-inventory-v1",
        sorted((str(item["relative_path"]), str(item["sha256"])) for item in root_entries),
    )
    if expected_byte_digest != root_manifest.get("release_byte_digest"):
        raise ArtifactIntegrityError("root manifest release_byte_digest does not reconcile")


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".parquet": "application/parquet",
        ".json": "application/json",
        ".jsonld": "application/ld+json",
        ".jsonl": "application/json",
        ".csv": "text/csv",
        ".xes": "application/xes+xml",
        ".md": "text/markdown",
        ".html": "text/html",
        ".zip": "application/zip",
    }
    try:
        return mapping[suffix]
    except KeyError as exc:
        raise ArtifactIntegrityError(f"artifact {path} has unsupported media extension {suffix!r}") from exc


def _record_count(path: Path, media_type: str) -> int | None:
    if path.suffix.lower() == ".jsonl":
        return sum(1 for line in path.read_bytes().splitlines() if line.strip())
    if media_type == "text/csv":
        return max(0, len(path.read_text(encoding="utf-8").splitlines()) - 1)
    if media_type == "application/xes+xml":
        return path.read_bytes().count(b"<event>")
    if media_type in {"application/json", "application/ld+json", "text/markdown", "text/html"}:
        return 1
    return None


def _custom_parquet_privacy(path: Path) -> str:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ArtifactIntegrityError("pyarrow is required to inspect custom Parquet privacy metadata") from exc
    parquet_file = pq.ParquetFile(path)
    try:
        metadata = parquet_file.schema_arrow.metadata or {}
        return (metadata.get(b"htgl.privacy_class") or b"").decode("utf-8")
    finally:
        parquet_file.close()


def _path_privacy(relative: str) -> str:
    if relative.startswith("config/") or relative.startswith("provenance/"):
        return "restricted"
    if relative.startswith("truth/") or "/evaluator/" in relative:
        return "evaluator_only"
    if relative.startswith("validation/"):
        return "restricted"
    if relative.startswith("metrics/") and "metadata" not in relative:
        return "restricted"
    return "public"


def _generation_stage(relative: str) -> str:
    top = PurePosixPath(relative).parts[0]
    return {
        "raw": "S04_physical",
        "canonical": "S02_S07_canonical",
        "truth": "S08_S10_truth",
        "observers": "S11_observer_projection",
        "samples": "S12_sampling",
        "validation": "S13_validation",
        "metrics": "S14_metrics",
        "adapters": "S15_adapter_compiler",
        "reports": "S15_report_compiler",
        "config": "S00_resolved_config",
        "schemas": "S00_contract_lock",
        "provenance": "S01_S15_provenance",
    }.get(top, "S15_artifact_compiler")
