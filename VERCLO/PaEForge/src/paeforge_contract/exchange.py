"""Canonical, immutable file exchange for the VERCLO input boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from .canonical import canonical_json_bytes
from .validation import ContractError, validate_verifier_bundle


FILENAMES = {
    "manifest": "case-manifest.json",
    "observer": "observer-projection.json",
    "receipts": "receipt-stream.json",
}


def _write_immutable(path: Path, document: Mapping[str, Any]) -> None:
    encoded = canonical_json_bytes(document)
    if path.exists():
        if path.is_file() and path.read_bytes() == encoded:
            return
        raise FileExistsError(f"refusing to replace non-identical exchange artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_verifier_bundle(
    output_directory: str | Path,
    manifest: Mapping[str, Any],
    observer_projection: Mapping[str, Any],
    receipt_stream: Mapping[str, Any],
) -> tuple[Path, Path, Path]:
    """Validate and atomically write a three-file verifier bundle."""

    validate_verifier_bundle(manifest, observer_projection, receipt_stream)
    root = Path(output_directory).resolve()
    paths = (root / FILENAMES["manifest"], root / FILENAMES["observer"], root / FILENAMES["receipts"])
    encoded_documents = tuple(
        canonical_json_bytes(document)
        for document in (manifest, observer_projection, receipt_stream)
    )
    for path, encoded in zip(paths, encoded_documents, strict=True):
        if path.exists() and (not path.is_file() or path.is_symlink() or path.read_bytes() != encoded):
            raise FileExistsError(f"refusing to replace non-identical exchange artifact: {path}")
    for path, document in zip(paths, (manifest, observer_projection, receipt_stream), strict=True):
        _write_immutable(path, document)
    return paths


def read_verifier_bundle(
    input_directory: str | Path, *, canary_values: tuple[str, ...] = ()
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """Read and revalidate exactly the documented VERCLO input files."""

    root = Path(input_directory).resolve()
    if not root.is_dir():
        raise ContractError(f"verifier bundle directory does not exist: {root}")
    expected_names = frozenset(FILENAMES.values())
    actual_names = {path.name for path in root.iterdir()}
    if actual_names != expected_names:
        raise ContractError(
            f"verifier bundle inventory mismatch: expected {sorted(expected_names)}, got {sorted(actual_names)}"
        )
    for name in expected_names:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ContractError(f"verifier bundle member must be a regular file: {name}")
    manifest = json.loads((root / FILENAMES["manifest"]).read_text(encoding="utf-8"))
    observer = json.loads((root / FILENAMES["observer"]).read_text(encoding="utf-8"))
    receipts = json.loads((root / FILENAMES["receipts"]).read_text(encoding="utf-8"))
    validate_verifier_bundle(manifest, observer, receipts, canary_values=canary_values)
    return manifest, observer, receipts
