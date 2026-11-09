"""Atomic authoritative writer for finalized S13 validation issues."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from htgl_dataset_generator.schemas import ContractSpec, load_contract
from htgl_dataset_generator.validation.models import ValidationBuild

from .parquet import write_parquet_table


@dataclass(frozen=True)
class ValidationArtifactWriteResult:
    root: Path
    validation_issue_path: Path
    metadata_path: Path
    metadata_sha256: str
    files: Mapping[str, Path]


def write_validation_artifact_bundle(
    build: ValidationBuild,
    output_dir: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
) -> ValidationArtifactWriteResult:
    """Write the complete issue ledger even when it intentionally blocks release."""

    schema_contract = contract if contract is not None else load_contract()
    root = Path(output_dir) / "validation"
    issue_path = write_parquet_table(
        "validation_issue",
        build.validation_issues,
        root / "validation_issue.parquet",
        contract=schema_contract,
        compression="ZSTD",
    )
    status_counts = Counter(str(row["status"]) for row in build.validation_issues)
    metadata = {
        "format": "htgl.validation.bundle.v1",
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
        "required_check_ids": list(build.required_check_ids),
        "executed_check_ids": list(build.executed_check_ids),
        "release_eligible": build.release_eligible,
        "status_counts": dict(sorted(status_counts.items())),
        "threshold_profile_id": build.threshold_profile_id,
        "threshold_profile_sha256": build.threshold_profile_sha256,
        "validation_issue_sha256": hashlib.sha256(issue_path.read_bytes()).hexdigest(),
        "claim_boundary": (
            "Validation evaluates benchmark artifacts and release preconditions only; it does not "
            "establish legal compliance, physical deletion, production cryptographic proof, HTGL "
            "execution, ledger anchoring, or utility deployment."
        ),
    }
    payload = (
        json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    metadata_path = root / "validation_metadata.json"
    _atomic_write(metadata_path, payload)
    return ValidationArtifactWriteResult(
        root=root,
        validation_issue_path=issue_path,
        metadata_path=metadata_path,
        metadata_sha256=hashlib.sha256(payload).hexdigest(),
        files={
            "validation_issue.parquet": issue_path,
            "validation_metadata.json": metadata_path,
        },
    )


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
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
