"""Named seed streams, deterministic IDs, and order-invariant RNG utilities.

This module intentionally avoids ``random``, ``uuid4``, process time, and
unordered iteration. Every generated value is derived from explicit run-plan
inputs and canonical JSON serialization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
import hashlib
import hmac
import json
import uuid

from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan, build_run_plan
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record


SEED_DERIVATION_ALGORITHM = "htgl-sha256-hmac-counter-v1"
ID_DERIVATION_ALGORITHM = "uuid5-sha256-canonical-v1"
BASE_UUID_NAMESPACE = uuid.UUID("2f4c2f24-7246-5a1f-b932-2db39bd41f1d")

DEFAULT_COMPONENT_STREAMS: tuple[str, ...] = (
    "S00.resolve",
    "S01.seeds",
    "S02.world",
    "S03.catalog",
    "S04.physical_raw",
    "S05.arrivals",
    "S06.workflows",
    "S07.policy",
    "S08.counterfactuals",
    "S09.obligations",
    "S10.evidence",
    "S11.projections",
    "S12.sampling",
    "S13.validate",
    "S14.metrics",
    "S15.compile",
    "P8.baselines",
)

CRN_COMPONENT_STREAMS: tuple[str, ...] = (
    "S05.arrivals",
    "S08.counterfactuals",
    "S11.projections",
    "S12.sampling",
    "S14.metrics",
    "P8.baselines",
)


@dataclass(frozen=True, order=True)
class SeedStreamSpec:
    """A deterministic component stream specification."""

    component: str
    partition: str = "global"
    common_random_group: str | None = None

    @property
    def is_common_random(self) -> bool:
        return self.common_random_group is not None


@dataclass(frozen=True)
class SeedDerivationInput:
    """Canonical input tuple for seed derivation."""

    root_seed: str
    contract_version: str
    scenario_id: str
    replicate_id: int
    component: str
    partition: str
    common_random_group: str | None = None

    def payload(self) -> dict[str, Any]:
        scenario_key = self.common_random_group or self.scenario_id
        return {
            "algorithm": SEED_DERIVATION_ALGORITHM,
            "common_random_group": self.common_random_group,
            "component": self.component,
            "contract_version": self.contract_version,
            "partition": self.partition,
            "replicate_id": self.replicate_id,
            "scenario_id": scenario_key,
        }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stream_name(plan: ResolvedRunPlan, spec: SeedStreamSpec) -> str:
    prefix = (
        f"crn={spec.common_random_group}"
        if spec.common_random_group is not None
        else f"scenario={plan.scenario_id}"
    )
    return (
        f"{prefix}|replicate={plan.replicate_id:04d}|"
        f"component={spec.component}|partition={spec.partition}"
    )


def _parent_stream_name(plan: ResolvedRunPlan, spec: SeedStreamSpec) -> str:
    prefix = (
        f"crn={spec.common_random_group}"
        if spec.common_random_group is not None
        else f"scenario={plan.scenario_id}"
    )
    return f"{prefix}|replicate={plan.replicate_id:04d}|component=S01.seeds|partition=root"


def derive_seed_material_hex(derivation_input: SeedDerivationInput) -> str:
    """Derive stable seed material from explicit run-plan inputs."""

    key = str(derivation_input.root_seed).encode("utf-8")
    message = _canonical_json(derivation_input.payload()).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def deterministic_uuid_namespace(seed_material_hex: str) -> str:
    """Derive a UUIDv5 namespace from seed material."""

    return str(uuid.uuid5(BASE_UUID_NAMESPACE, seed_material_hex))


def deterministic_uuid(
    namespace: str | uuid.UUID,
    entity_type: str,
    parts: Mapping[str, Any] | Sequence[Any] | str,
) -> str:
    """Return a deterministic UUIDv5 for an entity and canonical parts."""

    ns = uuid.UUID(str(namespace))
    payload = {
        "algorithm": ID_DERIVATION_ALGORITHM,
        "entity_type": entity_type,
        "parts": parts,
    }
    return str(uuid.uuid5(ns, _canonical_json(payload)))


def content_id(entity_type: str, content: Mapping[str, Any] | Sequence[Any] | str) -> str:
    """Return a content-derived, UUID-shaped stable identifier."""

    digest = hashlib.sha256(
        _canonical_json(
            {
                "algorithm": "htgl-content-id-sha256-v1",
                "content": content,
                "entity_type": entity_type,
            }
        ).encode("utf-8")
    ).hexdigest()
    return str(uuid.UUID(digest[:32]))


class CounterRng:
    """Order-invariant deterministic random bytes and numeric draws.

    Draws are addressed by ``label`` and ``index``. The caller therefore controls
    stream positions explicitly, which keeps values stable across worker count,
    partition scheduling, and record ordering.
    """

    def __init__(self, seed_material_hex: str) -> None:
        if len(seed_material_hex) != 64:
            raise ValueError("seed_material_hex must be a 32-byte SHA-256 hex digest")
        bytes.fromhex(seed_material_hex)
        self._seed_material_hex = seed_material_hex.lower()

    @property
    def seed_material_hex(self) -> str:
        return self._seed_material_hex

    def bytes(self, label: str, index: int, size: int = 32) -> bytes:
        if index < 0:
            raise ValueError("index must be non-negative")
        if size <= 0:
            raise ValueError("size must be positive")
        chunks: list[bytes] = []
        chunk_index = 0
        while sum(len(chunk) for chunk in chunks) < size:
            payload = _canonical_json(
                {
                    "algorithm": SEED_DERIVATION_ALGORITHM,
                    "chunk": chunk_index,
                    "index": index,
                    "label": label,
                }
            ).encode("utf-8")
            chunks.append(
                hmac.new(bytes.fromhex(self._seed_material_hex), payload, hashlib.sha256).digest()
            )
            chunk_index += 1
        return b"".join(chunks)[:size]

    def uint64(self, label: str, index: int) -> int:
        return int.from_bytes(self.bytes(label, index, 8), byteorder="big", signed=False)

    def uniform(self, label: str, index: int) -> float:
        # Use the top 53 bits to match IEEE-754 double precision mantissa.
        return (self.uint64(label, index) >> 11) / float(1 << 53)

    def randint(self, label: str, index: int, low: int, high: int) -> int:
        if low > high:
            raise ValueError("low must be <= high")
        span = high - low + 1
        return low + (self.uint64(label, index) % span)


def canonical_records_digest(records: Iterable[Mapping[str, Any]]) -> str:
    """Return an order-invariant digest for table-like records."""

    canonical_rows = sorted(_canonical_json(dict(record)) for record in records)
    return hashlib.sha256(
        _canonical_json(
            {
                "algorithm": "htgl-record-table-digest-v1",
                "rows": canonical_rows,
            }
        ).encode("utf-8")
    ).hexdigest()


def _standard_specs(components: Iterable[str], partitions: Iterable[str]) -> tuple[SeedStreamSpec, ...]:
    specs = [
        SeedStreamSpec(component=component, partition=partition)
        for component in components
        for partition in partitions
    ]
    return tuple(sorted(specs))


def _common_random_specs(
    groups: Iterable[str],
    components: Iterable[str],
    partitions: Iterable[str],
) -> tuple[SeedStreamSpec, ...]:
    specs = [
        SeedStreamSpec(component=component, partition=partition, common_random_group=group)
        for group in groups
        for component in components
        for partition in partitions
    ]
    return tuple(sorted(specs))


def _record_for_spec(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    spec: SeedStreamSpec,
    contract: ContractSpec,
) -> dict[str, Any]:
    derivation_input = SeedDerivationInput(
        root_seed=resolved.run.root_seed,
        contract_version=resolved.run.contract_version,
        scenario_id=plan.scenario_id,
        replicate_id=plan.replicate_id,
        component=spec.component,
        partition=spec.partition,
        common_random_group=spec.common_random_group,
    )
    seed_material = derive_seed_material_hex(derivation_input)
    record = {
        "run_id": resolved.run.run_id,
        "stream_name": _stream_name(plan, spec),
        "parent_stream_name": _parent_stream_name(plan, spec),
        "seed_material_hex": seed_material,
        "algorithm": SEED_DERIVATION_ALGORITHM,
        "deterministic_id_namespace": deterministic_uuid_namespace(seed_material),
    }
    validate_record(contract, "seed_stream", record)
    return record


def _root_record(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    *,
    contract: ContractSpec,
    common_random_group: str | None = None,
) -> dict[str, Any]:
    spec = SeedStreamSpec(
        component="S01.seeds",
        partition="root",
        common_random_group=common_random_group,
    )
    derivation_input = SeedDerivationInput(
        root_seed=resolved.run.root_seed,
        contract_version=resolved.run.contract_version,
        scenario_id=plan.scenario_id,
        replicate_id=plan.replicate_id,
        component=spec.component,
        partition=spec.partition,
        common_random_group=common_random_group,
    )
    seed_material = derive_seed_material_hex(derivation_input)
    record = {
        "run_id": resolved.run.run_id,
        "stream_name": _parent_stream_name(plan, spec),
        "parent_stream_name": None,
        "seed_material_hex": seed_material,
        "algorithm": SEED_DERIVATION_ALGORITHM,
        "deterministic_id_namespace": deterministic_uuid_namespace(seed_material),
    }
    validate_record(contract, "seed_stream", record)
    return record


def seed_stream_records_for_plan(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    *,
    component_streams: Iterable[str] = DEFAULT_COMPONENT_STREAMS,
    partitions: Iterable[str] = ("global",),
    include_common_random_groups: bool = True,
    common_random_components: Iterable[str] = CRN_COMPONENT_STREAMS,
    contract: ContractSpec | None = None,
) -> tuple[dict[str, Any], ...]:
    """Emit seed-stream table rows for one scenario/replicate plan."""

    schema_contract = contract if contract is not None else load_contract()
    records: list[dict[str, Any]] = [_root_record(resolved, plan, contract=schema_contract)]
    for spec in _standard_specs(component_streams, partitions):
        records.append(_record_for_spec(resolved, plan, spec, schema_contract))

    if include_common_random_groups:
        for group in sorted(resolved.sampling.common_random_groups):
            records.append(
                _root_record(
                    resolved,
                    plan,
                    contract=schema_contract,
                    common_random_group=group,
                )
            )
        for spec in _common_random_specs(
            sorted(resolved.sampling.common_random_groups),
            common_random_components,
            partitions,
        ):
            records.append(_record_for_spec(resolved, plan, spec, schema_contract))
    return tuple(sorted(records, key=lambda row: row["stream_name"]))


def seed_stream_records(
    resolved: ResolvedConfig,
    *,
    plans: Iterable[ResolvedRunPlan] | None = None,
    component_streams: Iterable[str] = DEFAULT_COMPONENT_STREAMS,
    partitions: Iterable[str] = ("global",),
    include_common_random_groups: bool = True,
    common_random_components: Iterable[str] = CRN_COMPONENT_STREAMS,
    contract: ContractSpec | None = None,
) -> tuple[dict[str, Any], ...]:
    """Emit all seed-stream rows for the resolved config.

    The returned records are schema-valid rows for ``seed_stream.parquet`` and
    can be materialized with the schema-bound Parquet writer when available.
    """

    schema_contract = contract if contract is not None else load_contract()
    run_plans = tuple(plans) if plans is not None else build_run_plan(resolved)
    records: list[dict[str, Any]] = []
    for plan in sorted(run_plans, key=lambda item: (item.scenario_id, item.replicate_id)):
        records.extend(
            seed_stream_records_for_plan(
                resolved,
                plan,
                component_streams=component_streams,
                partitions=partitions,
                include_common_random_groups=include_common_random_groups,
                common_random_components=common_random_components,
                contract=schema_contract,
            )
        )
    return tuple(sorted(records, key=lambda row: row["stream_name"]))
