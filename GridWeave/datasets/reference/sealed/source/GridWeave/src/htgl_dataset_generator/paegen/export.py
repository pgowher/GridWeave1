"""Fail-closed export with physical oracle/observer separation."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from htgl_dataset_generator.artifacts.canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
    sha256_hex,
)

from .models import PaEGenBuild, PaEGenExportResult


def _write_immutable(path: Path, payload: Mapping[str, object]) -> None:
    encoded = canonical_json_bytes(payload)
    if path.exists():
        if path.is_file() and sha256_hex(path.read_bytes()) == sha256_hex(encoded):
            return
        raise FileExistsError(f"refusing to replace non-identical PaEGen artifact: {path}")
    atomic_write_bytes(path, encoded)


def export_paegen(build: PaEGenBuild, output_root: str | Path) -> PaEGenExportResult:
    """Write sealed truth and observer inputs into non-overlapping directory trees."""

    root = Path(output_root).resolve()
    sealed_root = root / "sealed-ground-truth"
    observer_root = root / "observer-input"
    manifest_root = root / "manifests"
    digest_rows: list[dict[str, object]] = []
    for replica in build.replicas:
        partition = Path(replica.scenario_id) / f"replicate-{replica.replicate_id:04d}"
        truth_path = sealed_root / partition / "ground-truth.json"
        _write_immutable(truth_path, replica.ground_truth.payload)
        digest_rows.append({"path": truth_path.relative_to(root).as_posix(), "sha256": replica.ground_truth.sha256})
        for profile_id, observer in replica.observer_views.items():
            view_path = observer_root / partition / profile_id / "observable-view.json"
            _write_immutable(view_path, observer.payload)
            digest_rows.append({"path": view_path.relative_to(root).as_posix(), "sha256": observer.sha256})
        manifest_path = manifest_root / partition / "scenario-manifest.json"
        _write_immutable(manifest_path, replica.scenario_manifest.payload)
        digest_rows.append({"path": manifest_path.relative_to(root).as_posix(), "sha256": replica.scenario_manifest.sha256})
    digest_rows.sort(key=lambda row: str(row["path"]))
    return PaEGenExportResult(
        output_root=root,
        sealed_ground_truth_root=sealed_root,
        observer_input_root=observer_root,
        manifest_root=manifest_root,
        file_count=len(digest_rows),
        export_digest=domain_sha256("paegen-export-v1", digest_rows),
    )

