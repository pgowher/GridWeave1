"""Deterministic source registry for publication provenance and licence gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any, Mapping

from htgl_dataset_generator.config.release_profiles import ReleaseProfile


SOURCE_REGISTRY_FORMAT = "htgl.source-registry.v1"
CONTROLLED_SYNTHETIC_LICENCE_STATUS = (
    "not_applicable_generator_owned_synthetic_definition"
)
EXTERNAL_SOURCE_LABELS = frozenset(
    {
        "calibrated_from_source",
        "imported_template",
        "publication_derived",
        "deployment_measured",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SourceRegistryError(ValueError):
    """Raised when provenance cannot support the selected release profile."""


@dataclass(frozen=True)
class SourceLicence:
    licence_id: str
    licence_name: str
    licence_uri: str | None
    status: str
    redistribution_allowed: bool | None
    attribution_required: bool | None
    review_note: str


@dataclass(frozen=True)
class SourceTransformation:
    transformation_id: str
    transformation_version: str
    implementation_id: str
    description: str
    input_source_ids: tuple[str, ...]
    output_parameter_paths: tuple[str, ...]
    transformation_sha256: str


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    source_kind: str
    source_label: str
    title: str
    version: str
    source_uri: str | None
    source_content_sha256: str
    observed_date_range: str | None
    geography: str
    uncertainty_statement: str
    synthetic_record_content_included: bool
    transformation: SourceTransformation
    licence: SourceLicence


@dataclass(frozen=True)
class SourceRegistry:
    registry_format: str
    registry_id: str
    registry_version: str
    run_id: str
    config_sha256: str
    release_profile_id: str
    release_profile_sha256: str
    records: tuple[SourceRecord, ...]
    registry_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_source_registry(resolved: Any, profile: ReleaseProfile) -> SourceRegistry:
    """Build complete provenance for the controlled-synthetic release profile."""

    records: list[SourceRecord] = []
    physical_paths = tuple(
        sorted(
            path
            for path in resolved.source_labels
            if path.startswith("/physical/") or path == "/run/calibration_profile_id"
        )
    )
    records.append(
        _controlled_record(
            source_id=resolved.physical.calibration_bundle_id,
            source_kind="controlled_synthetic_parameter_bundle",
            title="Controlled procedural physical parameter bundle",
            version=resolved.physical.backend_version,
            output_parameter_paths=physical_paths,
            config_sha256=resolved.config_sha256,
            implementation_id="htgl_dataset_generator.physical.ProceduralPhysicalBackend",
            description=(
                "Direct procedural parameterization from the resolved configuration; no "
                "observed source records, imported templates, or learned model are used."
            ),
        )
    )
    for source_id in sorted(resolved.physical.calibration_source_ids):
        records.append(
            _controlled_record(
                source_id=source_id,
                source_kind="controlled_synthetic_parameter_source",
                title="Generator-owned controlled synthetic physical source label",
                version="v1",
                output_parameter_paths=physical_paths,
                config_sha256=resolved.config_sha256,
                implementation_id="htgl_dataset_generator.physical.ProceduralPhysicalBackend",
                description=(
                    "Identifier for generator-owned procedural parameters. It is not an "
                    "external calibration dataset identifier."
                ),
            )
        )
    policy_paths = tuple(
        sorted(path for path in resolved.source_labels if path.startswith("/policy/"))
    )
    for source_id in sorted(resolved.policy.rule_source_ids):
        records.append(
            _controlled_record(
                source_id=source_id,
                source_kind="controlled_experimental_policy_source",
                title="Generator-owned experimental policy-profile source label",
                version=resolved.policy.profile_version,
                output_parameter_paths=policy_paths,
                config_sha256=resolved.config_sha256,
                implementation_id="htgl_dataset_generator.policy.SafePolicyEvaluator",
                description=(
                    "Locally authored experimental rule-package provenance. The identifier "
                    "does not import legal text and does not establish legal compliance."
                ),
            )
        )
    registry_owned_paths = set(physical_paths) | set(policy_paths)
    general_paths = tuple(sorted(set(resolved.source_labels) - registry_owned_paths))
    records.append(
        _controlled_record(
            source_id="CONTROLLED-SYNTHETIC-CONFIG-v1",
            source_kind="controlled_synthetic_configuration_definition",
            title="Generator-owned controlled synthetic configuration definitions",
            version="1.0.0",
            output_parameter_paths=general_paths,
            config_sha256=resolved.config_sha256,
            implementation_id="htgl_dataset_generator.config.resolve_config_file",
            description=(
                "Resolved generator-owned parameters not associated with an external "
                "dataset, publication-derived value, imported template, or deployment "
                "measurement. Every path is explicitly labelled controlled_synthetic."
            ),
        )
    )
    core = {
        "registry_format": SOURCE_REGISTRY_FORMAT,
        "registry_id": f"SOURCE-REGISTRY-{resolved.run.run_id}",
        "registry_version": "1.0.0",
        "run_id": resolved.run.run_id,
        "config_sha256": resolved.config_sha256,
        "release_profile_id": profile.profile_id,
        "release_profile_sha256": profile.profile_sha256,
        "records": [asdict(item) for item in sorted(records, key=lambda item: item.source_id)],
    }
    registry = SourceRegistry(
        registry_format=SOURCE_REGISTRY_FORMAT,
        registry_id=str(core["registry_id"]),
        registry_version=str(core["registry_version"]),
        run_id=resolved.run.run_id,
        config_sha256=resolved.config_sha256,
        release_profile_id=profile.profile_id,
        release_profile_sha256=profile.profile_sha256,
        records=tuple(sorted(records, key=lambda item: item.source_id)),
        registry_sha256=_digest(core),
    )
    validate_source_registry(registry, resolved=resolved, profile=profile)
    return registry


def validate_source_registry(
    registry: SourceRegistry,
    *,
    resolved: Any,
    profile: ReleaseProfile,
) -> None:
    if registry.registry_format != SOURCE_REGISTRY_FORMAT:
        raise SourceRegistryError("unknown source registry format")
    if registry.config_sha256 != resolved.config_sha256:
        raise SourceRegistryError("source registry config digest mismatch")
    if registry.release_profile_sha256 != profile.profile_sha256:
        raise SourceRegistryError("source registry release-profile digest mismatch")
    ids = [item.source_id for item in registry.records]
    if len(ids) != len(set(ids)):
        raise SourceRegistryError("source registry contains duplicate source IDs")
    expected_ids = {
        "CONTROLLED-SYNTHETIC-CONFIG-v1",
        resolved.physical.calibration_bundle_id,
        *resolved.physical.calibration_source_ids,
        *resolved.policy.rule_source_ids,
    }
    if set(ids) != expected_ids:
        raise SourceRegistryError(
            "source registry coverage mismatch "
            f"missing={sorted(expected_ids-set(ids))} extra={sorted(set(ids)-expected_ids)}"
        )
    covered_paths = {
        path
        for record in registry.records
        for path in record.transformation.output_parameter_paths
    }
    expected_paths = set(resolved.source_labels)
    if covered_paths != expected_paths:
        raise SourceRegistryError(
            "source registry parameter coverage mismatch "
            f"missing={sorted(expected_paths-covered_paths)[:16]} "
            f"extra={sorted(covered_paths-expected_paths)[:16]}"
        )
    for record in registry.records:
        if record.source_label in EXTERNAL_SOURCE_LABELS:
            raise SourceRegistryError(
                f"{record.source_id}: external source label is not permitted by {profile.profile_id}"
            )
        if record.source_label != "controlled_synthetic":
            raise SourceRegistryError(
                f"{record.source_id}: unsupported source label {record.source_label!r}"
            )
        if record.source_uri is not None or record.observed_date_range is not None:
            raise SourceRegistryError(
                f"{record.source_id}: controlled synthetic records cannot claim observed-source metadata"
            )
        if record.synthetic_record_content_included:
            raise SourceRegistryError(
                f"{record.source_id}: source registry must not embed source record content"
            )
        if record.licence.status != CONTROLLED_SYNTHETIC_LICENCE_STATUS:
            raise SourceRegistryError(
                f"{record.source_id}: invalid controlled-synthetic licence status"
            )
        if record.licence.redistribution_allowed is not None:
            raise SourceRegistryError(
                f"{record.source_id}: external redistribution permission is not applicable"
            )
        if not SHA256_RE.fullmatch(record.source_content_sha256):
            raise SourceRegistryError(f"{record.source_id}: invalid source content digest")
        if not SHA256_RE.fullmatch(record.transformation.transformation_sha256):
            raise SourceRegistryError(f"{record.source_id}: invalid transformation digest")
        if not record.transformation.output_parameter_paths:
            raise SourceRegistryError(f"{record.source_id}: no output parameter paths")
    core = registry.as_dict()
    observed_digest = str(core.pop("registry_sha256"))
    if _digest(core) != observed_digest:
        raise SourceRegistryError("source registry digest mismatch")


def _controlled_record(
    *,
    source_id: str,
    source_kind: str,
    title: str,
    version: str,
    output_parameter_paths: tuple[str, ...],
    config_sha256: str,
    implementation_id: str,
    description: str,
) -> SourceRecord:
    transformation_core = {
        "transformation_id": f"TRANSFORM-{source_id}",
        "transformation_version": "1.0.0",
        "implementation_id": implementation_id,
        "description": description,
        "input_source_ids": (),
        "output_parameter_paths": output_parameter_paths,
    }
    transformation = SourceTransformation(
        **transformation_core,
        transformation_sha256=_digest(transformation_core),
    )
    return SourceRecord(
        source_id=source_id,
        source_kind=source_kind,
        source_label="controlled_synthetic",
        title=title,
        version=version,
        source_uri=None,
        source_content_sha256=_digest(
            {
                "domain": "controlled-synthetic-source-definition-v1",
                "source_id": source_id,
                "config_sha256": config_sha256,
                "output_parameter_paths": output_parameter_paths,
            }
        ),
        observed_date_range=None,
        geography="configured synthetic regions only; no observed-source geography",
        uncertainty_statement=(
            "Stochastic variation is controlled by named seed streams; no empirical "
            "source-calibration uncertainty is claimed."
        ),
        synthetic_record_content_included=False,
        transformation=transformation,
        licence=SourceLicence(
            licence_id="LICENCE-CONTROLLED-SYNTHETIC-DEFINITION-v1",
            licence_name="No external dataset licence applicable",
            licence_uri=None,
            status=CONTROLLED_SYNTHETIC_LICENCE_STATUS,
            redistribution_allowed=None,
            attribution_required=None,
            review_note=(
                "This status covers generator-owned synthetic definitions only and is not "
                "a legal opinion about software or downstream artifact licensing."
            ),
        ),
    )


def _digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
