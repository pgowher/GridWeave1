"""Physically separated export of paired adversarial fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from htgl_dataset_generator.artifacts.canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
    sha256_hex,
)

from .compiler import AdversarialCampaign


@dataclass(frozen=True)
class AdversarialExportResult:
    output_root: Path
    file_count: int
    export_digest: str


def _write(path: Path, payload: Mapping[str, object]) -> str:
    encoded = canonical_json_bytes(payload)
    digest = sha256_hex(encoded)
    if path.exists():
        if not path.is_file() or sha256_hex(path.read_bytes()) != digest:
            raise FileExistsError(f"refusing to replace non-identical campaign artifact: {path}")
        return digest
    atomic_write_bytes(path, encoded)
    return digest


def export_adversarial_campaign(
    campaign: AdversarialCampaign, output_root: str | Path
) -> AdversarialExportResult:
    """Export truth, expectations and observer views into non-overlapping trees."""

    root = Path(output_root).resolve()
    inventory: list[dict[str, str]] = []
    for fixture in campaign.fixtures:
        clean_path = root / "clean-ground-truth" / fixture.fixture_id / "ground-truth.json"
        attacked_path = root / "attacked-ground-truth" / fixture.fixture_id / "ground-truth.json"
        expectation_path = root / "expectations" / fixture.fixture_id / "expected.json"
        for path, payload in (
            (clean_path, fixture.clean_ground_truth.payload),
            (attacked_path, fixture.attacked_ground_truth.payload),
            (expectation_path, {
                "fixture_id": fixture.fixture_id,
                "attack_type": fixture.attack_type,
                "scenario_id": fixture.scenario_id,
                "clean_ground_truth_sha256": fixture.clean_ground_truth.sha256,
                "attacked_ground_truth_sha256": fixture.attacked_ground_truth.sha256,
                "expected_oracle_outcome": fixture.expected_oracle_outcome,
                "expected_verifier_outcome": fixture.expected_verifier_outcome,
                "expected_detection": fixture.expected_detection,
                "indistinguishability_class": fixture.indistinguishability_class,
            }),
        ):
            inventory.append({"path": path.relative_to(root).as_posix(), "sha256": _write(path, payload)})
        for profile_id, observer in fixture.observer_views.items():
            path = root / "observer-input" / fixture.fixture_id / profile_id / "observable-view.json"
            inventory.append({"path": path.relative_to(root).as_posix(), "sha256": _write(path, observer.payload)})
    inventory.sort(key=lambda item: item["path"])
    manifest = {
        "schema_version": "1.0.0",
        "control_digest": campaign.control_digest,
        "fixture_count": len(campaign.fixtures),
        "files": inventory,
    }
    manifest_path = root / "campaign-manifest.json"
    inventory.append({"path": manifest_path.relative_to(root).as_posix(), "sha256": _write(manifest_path, manifest)})
    return AdversarialExportResult(
        output_root=root,
        file_count=len(inventory),
        export_digest=domain_sha256("paebench-adversarial-export-v1", inventory),
    )

