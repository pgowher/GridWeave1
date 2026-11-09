"""Deterministic restricted persistence for external S15 release evidence."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.metrics import (
    PhysicalCalibrationReference,
    PhysicalReferenceObservation,
    PrivacySourceReference,
)
from htgl_dataset_generator.validation import (
    PerformanceObservation,
    StagePerformanceObservation,
)

from .canonical import atomic_write_bytes, canonical_json_bytes
from .models import (
    ArtifactIntegrityError,
    DownstreamReplayObservation,
    ReleaseEvidence,
)


RELEASE_EVIDENCE_FORMAT = "htgl.release-evidence.v1"
RELEASE_EVIDENCE_PATH = "provenance/release_evidence.json"
_CLAIM_BOUNDARY = (
    "External observations close validation, metrics, reproduction, and bounded replay "
    "claims only; they do not alter deterministic generation semantics."
)
_PAYLOAD_KEYS = frozenset(
    {
        "format",
        "run_id",
        "config_sha256",
        "performance_by_run",
        "physical_reference_by_run",
        "privacy_reference_by_run",
        "downstream_replay_by_run",
        "evidence_is_generation_input",
        "claim_boundary",
    }
)


def write_release_evidence(
    root: Path,
    evidence: ReleaseEvidence,
    *,
    run_id: str,
    config_sha256: str,
) -> Path:
    """Persist measured/calibrated inputs needed for exact release reproduction."""

    payload = release_evidence_payload(
        evidence,
        run_id=run_id,
        config_sha256=config_sha256,
    )
    path = root / RELEASE_EVIDENCE_PATH
    atomic_write_bytes(path, canonical_json_bytes(payload))
    return path


def release_evidence_payload(
    evidence: ReleaseEvidence,
    *,
    run_id: str,
    config_sha256: str,
) -> dict[str, Any]:
    return {
        "format": RELEASE_EVIDENCE_FORMAT,
        "run_id": run_id,
        "config_sha256": config_sha256,
        "performance_by_run": _mapping_rows(evidence.performance_by_run),
        "physical_reference_by_run": _mapping_rows(
            evidence.physical_reference_by_run or {}
        ),
        "privacy_reference_by_run": _mapping_rows(
            evidence.privacy_reference_by_run or {}
        ),
        "downstream_replay_by_run": _mapping_rows(
            evidence.downstream_replay_by_run or {}
        ),
        "evidence_is_generation_input": False,
        "claim_boundary": _CLAIM_BOUNDARY,
    }


def read_release_evidence(
    path: str | Path,
    *,
    expected_run_id: str,
    expected_config_sha256: str,
) -> ReleaseEvidence:
    """Read and strictly reconstruct a persisted release-evidence contract."""

    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ArtifactIntegrityError(
            f"cannot read release evidence {source}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ArtifactIntegrityError("release evidence root must be an object")
    if frozenset(payload) != _PAYLOAD_KEYS:
        raise ArtifactIntegrityError(
            "release evidence fields do not match the versioned contract: "
            f"observed={sorted(payload)} expected={sorted(_PAYLOAD_KEYS)}"
        )
    expected = {
        "format": RELEASE_EVIDENCE_FORMAT,
        "run_id": expected_run_id,
        "config_sha256": expected_config_sha256,
        "evidence_is_generation_input": False,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    disagreements = {
        key: {"observed": payload.get(key), "expected": value}
        for key, value in expected.items()
        if payload.get(key) != value
    }
    if disagreements:
        raise ArtifactIntegrityError(
            f"release evidence identity/semantics mismatch: {disagreements}"
        )
    performance = _decode_mapping(
        payload,
        "performance_by_run",
        _performance_observation,
    )
    if not performance:
        raise ArtifactIntegrityError("release evidence performance_by_run cannot be empty")
    return ReleaseEvidence(
        performance_by_run=performance,
        physical_reference_by_run=_decode_optional_mapping(
            payload,
            "physical_reference_by_run",
            _physical_reference,
        ),
        privacy_reference_by_run=_decode_optional_mapping(
            payload,
            "privacy_reference_by_run",
            lambda value: PrivacySourceReference(
                reference_id=str(value["reference_id"]),
                source_label=str(value["source_label"]),
                canonical_record_digests=tuple(value["canonical_record_digests"]),
                comparable_released_record_digests=tuple(
                    value["comparable_released_record_digests"]
                ),
            ),
        ),
        downstream_replay_by_run=_decode_optional_mapping(
            payload,
            "downstream_replay_by_run",
            lambda value: DownstreamReplayObservation(**value),
        ),
    )


def _mapping_rows(values: Mapping[tuple[str, int], Any]) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": scenario_id,
            "replicate_id": replicate_id,
            "value": asdict(value),
        }
        for (scenario_id, replicate_id), value in sorted(values.items())
    ]


def _decode_mapping(
    payload: Mapping[str, Any],
    field: str,
    factory: Any,
) -> dict[tuple[str, int], Any]:
    raw = payload.get(field)
    if not isinstance(raw, list):
        raise ArtifactIntegrityError(f"release evidence {field} must be an array")
    result: dict[tuple[str, int], Any] = {}
    for index, row in enumerate(raw):
        if not isinstance(row, dict) or not isinstance(row.get("value"), dict):
            raise ArtifactIntegrityError(
                f"release evidence {field}[{index}] must contain an object value"
            )
        if set(row) != {"scenario_id", "replicate_id", "value"}:
            raise ArtifactIntegrityError(
                f"release evidence {field}[{index}] has unknown or missing fields"
            )
        scenario_id = row["scenario_id"]
        replicate_id = row["replicate_id"]
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ArtifactIntegrityError(
                f"release evidence {field}[{index}] scenario_id must be non-empty"
            )
        if (
            isinstance(replicate_id, bool)
            or not isinstance(replicate_id, int)
            or replicate_id < 0
        ):
            raise ArtifactIntegrityError(
                f"release evidence {field}[{index}] replicate_id must be non-negative int"
            )
        key = (scenario_id, replicate_id)
        if key in result:
            raise ArtifactIntegrityError(
                f"release evidence {field} contains duplicate run key {key}"
            )
        try:
            result[key] = factory(dict(row["value"]))
        except Exception as exc:
            raise ArtifactIntegrityError(
                f"release evidence {field}[{index}] is invalid: {exc}"
            ) from exc
    return dict(sorted(result.items()))


def _decode_optional_mapping(
    payload: Mapping[str, Any],
    field: str,
    factory: Any,
) -> dict[tuple[str, int], Any] | None:
    decoded = _decode_mapping(payload, field, factory)
    return decoded or None


def _physical_reference(value: Mapping[str, Any]) -> PhysicalCalibrationReference:
    observations = value.get("observations")
    if not isinstance(observations, list):
        raise ValueError("physical reference observations must be an array")
    return PhysicalCalibrationReference(
        reference_id=str(value["reference_id"]),
        source_label=str(value["source_label"]),
        observations=tuple(
            PhysicalReferenceObservation(**dict(observation))
            for observation in observations
        ),
        acf_lags=tuple(int(item) for item in value["acf_lags"]),
    )


def _performance_observation(value: Mapping[str, Any]) -> PerformanceObservation:
    normalized = dict(value)
    stages = normalized.get("stage_observations", [])
    if not isinstance(stages, list):
        raise ValueError("performance stage_observations must be an array")
    normalized["stage_observations"] = tuple(
        StagePerformanceObservation(
            **{
                **dict(stage),
                "table_record_digests": tuple(
                    tuple(item) for item in stage.get("table_record_digests", [])
                ),
                "artifact_sha256": tuple(
                    tuple(item) for item in stage.get("artifact_sha256", [])
                ),
            }
        )
        for stage in stages
    )
    return PerformanceObservation(**normalized)
