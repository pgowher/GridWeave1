"""S02 federated world builder.

The builder emits canonical scenario-scoped records for ``actor``,
``actor_relationship``, and ``prosumer_cohort``. It represents large
populations through weighted cohorts and scaled institutional topology; it
never materializes one Python object per represented person.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import ceil, sqrt
from typing import Any, Iterable, Mapping
import hashlib
import json
import re

from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import (
    CounterRng,
    deterministic_uuid,
    seed_stream_records_for_plan,
)


WORLD_COMPONENT = "S02.world"
SCALE_CONTROLLER_THRESHOLD = 1_000_000

INSTITUTIONAL_CLASSES: tuple[str, ...] = (
    "dso",
    "tso",
    "supplier",
    "aggregator",
    "regulator",
    "vendor",
    "auditor",
    "processor",
)

OPTIONAL_INSTITUTIONAL_CLASSES: tuple[str, ...] = ("validator", "oversight")

ACTOR_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "consumer": ("requester",),
    "prosumer": ("requester", "issuer"),
    "dso": ("controller", "custodian", "issuer", "observer"),
    "tso": ("controller", "oversight", "observer"),
    "supplier": ("processor", "requester", "custodian"),
    "aggregator": ("processor", "requester", "custodian"),
    "regulator": ("oversight", "observer", "issuer"),
    "vendor": ("processor",),
    "auditor": ("auditor", "observer"),
    "processor": ("processor", "custodian"),
    "validator": ("validator", "observer"),
    "oversight": ("oversight", "observer", "validator"),
}

RELATIONSHIP_RULES: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "controls": (("dso", "tso"), ("consumer", "prosumer")),
    "processes_for": (
        ("processor", "vendor", "supplier", "aggregator"),
        ("dso", "supplier", "aggregator"),
    ),
    "supplies": (("supplier",), ("consumer", "prosumer")),
    "aggregates": (("aggregator",), ("prosumer",)),
    "oversees": (
        ("regulator", "tso", "oversight", "validator"),
        ("dso", "supplier", "aggregator", "processor", "vendor"),
    ),
    "audits": (
        ("auditor", "regulator"),
        ("dso", "supplier", "aggregator", "processor", "vendor"),
    ),
    "discloses_to": (
        ("dso", "supplier", "aggregator", "processor", "vendor"),
        ("regulator", "auditor", "tso", "oversight"),
    ),
}

DWELLING_BY_PROFILE_TOKEN: tuple[tuple[str, str], ...] = (
    ("urban", "apartment"),
    ("suburban", "single_family"),
    ("rural", "rural_detached"),
    ("ami", "mixed_residential"),
)

DER_BASE_BY_DWELLING: Mapping[str, float] = {
    "apartment": 0.10,
    "single_family": 0.24,
    "rural_detached": 0.34,
    "mixed_residential": 0.20,
}

INSTITUTION_POPULATION_DIVISOR: Mapping[str, int] = {
    "dso": 7_500_000,
    "tso": 100_000_000,
    "supplier": 10_000_000,
    "aggregator": 8_000_000,
    "regulator": 50_000_000,
    "vendor": 15_000_000,
    "auditor": 25_000_000,
    "processor": 12_000_000,
    "validator": 50_000_000,
    "oversight": 50_000_000,
}


class WorldBuildError(ValueError):
    """Raised when a federated world cannot satisfy the S02 contract."""


@dataclass(frozen=True)
class TopologyDiagnostics:
    scenario_id: str
    represented_population: int
    materialized_actor_count: int
    materialized_network_area_count: int
    materialized_cohort_count: int
    actor_counts_by_class: Mapping[str, int]
    relationship_counts_by_type: Mapping[str, int]
    represented_counts_by_region: Mapping[str, int]
    controller_actor_count: int
    max_controller_represented_population: int


@dataclass(frozen=True)
class FederatedWorld:
    actors: tuple[dict[str, Any], ...]
    actor_relationships: tuple[dict[str, Any], ...]
    prosumer_cohorts: tuple[dict[str, Any], ...]
    diagnostics: Mapping[str, TopologyDiagnostics]
    network_areas: tuple[dict[str, Any], ...] = ()

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "actor": self.actors,
            "actor_relationship": self.actor_relationships,
            "prosumer_cohort": self.prosumer_cohorts,
            "network_area": self.network_areas,
        }


@dataclass(frozen=True)
class _WorldContext:
    resolved: ResolvedConfig
    scenario_id: str
    namespace: str
    rng: CounterRng
    contract: ContractSpec


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stable_score(namespace: str, label: str, payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "label": label,
                "namespace": namespace,
                "payload": payload,
            }
        ).encode("utf-8")
    ).hexdigest()


def _normalize_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _world_context(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
) -> _WorldContext:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    rows = seed_stream_records_for_plan(resolved, plan, contract=contract)
    suffix = f"component={WORLD_COMPONENT}|partition=global"
    for row in rows:
        if row["stream_name"].endswith(suffix):
            return _WorldContext(
                resolved=resolved,
                scenario_id=scenario_id,
                namespace=str(row["deterministic_id_namespace"]),
                rng=CounterRng(str(row["seed_material_hex"])),
                contract=contract,
            )
    raise WorldBuildError(f"{scenario_id}: missing {WORLD_COMPONENT} seed stream")


def _allocate_int(total: int, keys: tuple[str, ...], namespace: str, label: str) -> dict[str, int]:
    if total < 0:
        raise WorldBuildError(f"{label}: total must be non-negative")
    if not keys:
        raise WorldBuildError(f"{label}: at least one allocation key is required")
    base = total // len(keys)
    remainder = total % len(keys)
    allocation = {key: base for key in keys}
    ranked = sorted(
        keys,
        key=lambda key: _stable_score(namespace, label, {"key": key}),
    )
    for key in ranked[:remainder]:
        allocation[key] += 1
    return allocation


def _infer_region_scope(cohort_id: str, regions: tuple[str, ...]) -> tuple[str, ...] | None:
    normalized_cohort = _normalize_token(cohort_id)
    matched = []
    for region in regions:
        normalized_region = _normalize_token(region)
        region_tokens = {normalized_region}
        if normalized_region.startswith("R_"):
            region_tokens.add(normalized_region[2:])
        if any(token and token in normalized_cohort for token in region_tokens):
            matched.append(region)
    return tuple(matched) if matched else None


def _dwelling_type(raw_cohort: Mapping[str, Any]) -> str:
    explicit = raw_cohort.get("dwelling_type")
    if isinstance(explicit, str) and explicit:
        return explicit
    cohort_id = str(raw_cohort.get("cohort_id", "")).lower()
    for token, dwelling in DWELLING_BY_PROFILE_TOKEN:
        if token in cohort_id:
            return dwelling
    return "mixed_residential"


def _tariff_profile_id(raw_cohort: Mapping[str, Any], dwelling_type: str) -> str:
    explicit = raw_cohort.get("tariff_profile_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    return f"TARIFF-{_normalize_token(dwelling_type)}-v1"


def _subject_scope(raw_cohort: Mapping[str, Any]) -> str:
    explicit = raw_cohort.get("subject_scope")
    if isinstance(explicit, str) and explicit:
        return explicit
    return "household"


def _climate_zone_id(raw_cohort: Mapping[str, Any], region_id: str) -> str:
    explicit = raw_cohort.get("climate_zone_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    return f"CLIMATE-{_normalize_token(region_id)}"


def _der_fraction(
    ctx: _WorldContext,
    raw_cohort: Mapping[str, Any],
    dwelling_type: str,
    region_id: str,
    ordinal: int,
) -> float:
    explicit = raw_cohort.get("der_adoption_fraction")
    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool):
        fraction = float(explicit)
    else:
        base = DER_BASE_BY_DWELLING.get(dwelling_type, 0.18)
        region_adjustment = (ctx.rng.uniform(f"der:{region_id}:{dwelling_type}", ordinal) - 0.5) * 0.04
        fraction = base + region_adjustment
    if not 0 <= fraction <= 1:
        raise WorldBuildError(
            f"{ctx.scenario_id}: DER adoption fraction must be in [0, 1], got {fraction}"
        )
    return round(max(0.0, min(1.0, fraction)), 4)


def _calibration_source_id(ctx: _WorldContext, ordinal: int) -> str | None:
    source_ids = tuple(ctx.resolved.physical.calibration_source_ids)
    if not source_ids:
        return None
    index = ctx.rng.randint("cohort-calibration-source", ordinal, 0, len(source_ids) - 1)
    return source_ids[index]


def _build_cohorts(ctx: _WorldContext) -> tuple[dict[str, Any], ...]:
    regions = tuple(ctx.resolved.world.regions)
    if not regions:
        raise WorldBuildError(f"{ctx.scenario_id}: at least one region is required")
    configured_total = 0
    rows: list[dict[str, Any]] = []
    split_ordinal = 0

    for raw_index, raw_cohort in enumerate(ctx.resolved.world.cohorts):
        if not isinstance(raw_cohort, Mapping):
            raise WorldBuildError(f"{ctx.scenario_id}: cohort {raw_index} must be an object")
        base_cohort_id = str(raw_cohort.get("cohort_id", "")).strip()
        if not base_cohort_id:
            raise WorldBuildError(f"{ctx.scenario_id}: cohort {raw_index} missing cohort_id")
        represented_count = raw_cohort.get("represented_count")
        if not isinstance(represented_count, int) or isinstance(represented_count, bool):
            raise WorldBuildError(f"{ctx.scenario_id}: {base_cohort_id} missing integer represented_count")
        if represented_count <= 0:
            raise WorldBuildError(f"{ctx.scenario_id}: {base_cohort_id} represented_count must be positive")
        configured_total += represented_count

        explicit_region = raw_cohort.get("region_id")
        if isinstance(explicit_region, str) and explicit_region:
            scoped_regions = (explicit_region,)
        else:
            scoped_regions = _infer_region_scope(base_cohort_id, regions) or regions
        for region_id in scoped_regions:
            if region_id not in regions:
                raise WorldBuildError(f"{ctx.scenario_id}: cohort {base_cohort_id} uses unknown region {region_id!r}")

        region_allocations = _allocate_int(
            represented_count,
            tuple(scoped_regions),
            ctx.namespace,
            f"cohort-region:{base_cohort_id}",
        )
        for region_id in sorted(region_allocations):
            total = region_allocations[region_id]
            dwelling = _dwelling_type(raw_cohort)
            der_fraction = _der_fraction(ctx, raw_cohort, dwelling, region_id, split_ordinal)
            prosumer_count = int(round(total * der_fraction))
            consumer_count = total - prosumer_count
            tariff_profile_id = _tariff_profile_id(raw_cohort, dwelling)
            subject_scope = _subject_scope(raw_cohort)
            climate_zone_id = _climate_zone_id(raw_cohort, region_id)
            der_band = "none" if prosumer_count == 0 else ("high" if der_fraction >= 0.25 else "moderate")
            cohort_id = (
                base_cohort_id
                if len(scoped_regions) == 1
                else f"{base_cohort_id}__{_normalize_token(region_id)}"
            )
            row = {
                "cohort_id": cohort_id,
                "scenario_id": ctx.scenario_id,
                "region_id": region_id,
                "represented_consumer_count": consumer_count,
                "represented_prosumer_count": prosumer_count,
                "der_adoption_fraction": der_fraction,
                "dwelling_type": dwelling,
                "tariff_profile_id": tariff_profile_id,
                "climate_zone_id": climate_zone_id,
                "subject_scope": subject_scope,
                "sampling_stratum": (
                    f"{region_id}|{dwelling}|{tariff_profile_id}|{subject_scope}|der_{der_band}"
                ),
                "calibration_source_id": _calibration_source_id(ctx, split_ordinal),
            }
            validate_record(ctx.contract, "prosumer_cohort", row)
            rows.append(row)
            split_ordinal += 1

    if configured_total != ctx.resolved.claim_scale.represented_population:
        raise WorldBuildError(
            f"{ctx.scenario_id}: configured cohort represented_count total {configured_total} "
            f"does not equal represented_population {ctx.resolved.claim_scale.represented_population}"
        )
    return tuple(sorted(rows, key=lambda row: row["cohort_id"]))


def _jurisdiction_for_region(ctx: _WorldContext, region_id: str) -> str:
    regions = tuple(ctx.resolved.world.regions)
    jurisdictions = tuple(ctx.resolved.world.jurisdictions)
    if not jurisdictions:
        raise WorldBuildError(f"{ctx.scenario_id}: at least one jurisdiction is required")
    try:
        region_index = regions.index(region_id)
    except ValueError as exc:
        raise WorldBuildError(f"{ctx.scenario_id}: unknown region {region_id!r}") from exc
    return jurisdictions[region_index % len(jurisdictions)]


def _fault_domain_for_region(ctx: _WorldContext, region_id: str) -> str:
    fault_domains = tuple(ctx.resolved.world.fault_domains)
    if not fault_domains:
        raise WorldBuildError(f"{ctx.scenario_id}: at least one fault domain is required")
    region_index = tuple(ctx.resolved.world.regions).index(region_id)
    return fault_domains[region_index % len(fault_domains)]


def _trust_domain_for_class(ctx: _WorldContext, actor_class: str, ordinal: int) -> str:
    trust_domains = tuple(ctx.resolved.world.trust_domains)
    if not trust_domains:
        raise WorldBuildError(f"{ctx.scenario_id}: at least one trust domain is required")
    preferred_tokens = {
        "auditor": ("OVERSIGHT", "AUDIT"),
        "regulator": ("OVERSIGHT", "REG"),
        "validator": ("OVERSIGHT", "VALID"),
        "oversight": ("OVERSIGHT",),
        "supplier": ("MARKET",),
        "aggregator": ("MARKET",),
        "vendor": ("MARKET",),
        "consumer": ("UTILITY", "MARKET"),
        "prosumer": ("UTILITY", "MARKET"),
    }.get(actor_class, ("UTILITY",))
    for token in preferred_tokens:
        for trust_domain in trust_domains:
            if token in _normalize_token(trust_domain):
                return trust_domain
    return trust_domains[ordinal % len(trust_domains)]


def _configured_classes(resolved: ResolvedConfig) -> tuple[str, ...]:
    classes = []
    for raw_org in resolved.world.organizations:
        if isinstance(raw_org, Mapping):
            actor_class = raw_org.get("actor_class")
            if isinstance(actor_class, str) and actor_class:
                if actor_class not in ACTOR_CAPABILITIES:
                    raise WorldBuildError(f"unsupported configured actor_class {actor_class!r}")
                classes.append(actor_class)
    return tuple(sorted(set(classes)))


def _configured_org_ids_by_class(resolved: ResolvedConfig) -> Mapping[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for raw_org in resolved.world.organizations:
        if not isinstance(raw_org, Mapping):
            continue
        actor_class = raw_org.get("actor_class")
        organization_id = raw_org.get("organization_id")
        if isinstance(actor_class, str) and isinstance(organization_id, str) and organization_id:
            if actor_class not in ACTOR_CAPABILITIES:
                raise WorldBuildError(f"unsupported configured actor_class {actor_class!r}")
            grouped.setdefault(actor_class, []).append(organization_id)
    return {key: tuple(sorted(values)) for key, values in sorted(grouped.items())}


def _relationship_count_map(resolved: ResolvedConfig) -> Mapping[str, int]:
    counts: dict[str, int] = {}
    for key, value in sorted(resolved.world.actor_relationship_counts.items()):
        if not isinstance(key, str) or not key:
            raise WorldBuildError("relationship count keys must be non-empty strings")
        if not isinstance(value, int) or isinstance(value, bool):
            raise WorldBuildError(f"relationship count for {key!r} must be an integer")
        if value < 0:
            raise WorldBuildError(f"relationship count for {key!r} is negative")
        counts[key] = value
    return counts


def _institution_classes(ctx: _WorldContext) -> tuple[str, ...]:
    configured = set(_configured_classes(ctx.resolved))
    classes = set(INSTITUTIONAL_CLASSES)
    trust_domain_text = " ".join(ctx.resolved.world.trust_domains).upper()
    for actor_class in OPTIONAL_INSTITUTIONAL_CLASSES:
        if actor_class in configured or actor_class.upper() in trust_domain_text:
            classes.add(actor_class)
    return tuple(sorted(classes))


def _institution_count(ctx: _WorldContext, actor_class: str) -> int:
    regions = tuple(ctx.resolved.world.regions)
    population = ctx.resolved.claim_scale.represented_population
    max_relationship_count = max(_relationship_count_map(ctx.resolved).values(), default=0)
    relationship_floor = max(1, ceil(sqrt(max_relationship_count)))
    regional_floor = len(regions) if actor_class not in {"tso"} else max(1, ceil(len(regions) / 2))
    population_floor = ceil(population / INSTITUTION_POPULATION_DIVISOR[actor_class])
    configured_floor = len(_configured_org_ids_by_class(ctx.resolved).get(actor_class, ()))
    return max(regional_floor, relationship_floor, population_floor, configured_floor, 1)


def _actor_row(
    ctx: _WorldContext,
    *,
    actor_class: str,
    organization_id: str,
    region_id: str,
    ordinal_parts: Mapping[str, Any],
) -> dict[str, Any]:
    if actor_class not in ACTOR_CAPABILITIES:
        raise WorldBuildError(f"{ctx.scenario_id}: unsupported actor_class {actor_class!r}")
    actor_id = deterministic_uuid(
        ctx.namespace,
        "actor",
        {
            "actor_class": actor_class,
            "organization_id": organization_id,
            "region_id": region_id,
            "scenario_id": ctx.scenario_id,
            "ordinal_parts": dict(ordinal_parts),
        },
    )
    row = {
        "actor_id": actor_id,
        "scenario_id": ctx.scenario_id,
        "actor_class": actor_class,
        "organization_id": organization_id,
        "region_id": region_id,
        "jurisdiction_id": _jurisdiction_for_region(ctx, region_id),
        "fault_domain_id": _fault_domain_for_region(ctx, region_id),
        "trust_domain_id": _trust_domain_for_class(ctx, actor_class, int(ordinal_parts.get("ordinal", 0))),
        "capabilities": list(ACTOR_CAPABILITIES[actor_class]),
        "valid_from": ctx.resolved.run.horizon_start,
        "valid_to": ctx.resolved.run.horizon_end,
        "synthetic_source": "controlled_synthetic" if organization_id in _configured_org_ids_by_class(ctx.resolved).get(actor_class, ()) else "procedural",
    }
    validate_record(ctx.contract, "actor", row)
    return row


def _build_actors(ctx: _WorldContext, cohorts: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    regions = tuple(ctx.resolved.world.regions)

    for ordinal, cohort in enumerate(cohorts):
        region_id = str(cohort["region_id"])
        if int(cohort["represented_consumer_count"]) > 0:
            rows.append(
                _actor_row(
                    ctx,
                    actor_class="consumer",
                    organization_id=f"ORG-SUBJECT-{_normalize_token(region_id)}",
                    region_id=region_id,
                    ordinal_parts={"cohort_id": cohort["cohort_id"], "ordinal": ordinal, "scope": "consumer"},
                )
            )
        if int(cohort["represented_prosumer_count"]) > 0:
            rows.append(
                _actor_row(
                    ctx,
                    actor_class="prosumer",
                    organization_id=f"ORG-SUBJECT-{_normalize_token(region_id)}",
                    region_id=region_id,
                    ordinal_parts={"cohort_id": cohort["cohort_id"], "ordinal": ordinal, "scope": "prosumer"},
                )
            )

    configured_orgs = _configured_org_ids_by_class(ctx.resolved)
    for actor_class in _institution_classes(ctx):
        count = _institution_count(ctx, actor_class)
        configured_ids = configured_orgs.get(actor_class, ())
        for ordinal in range(count):
            region_id = regions[ordinal % len(regions)]
            organization_id = (
                configured_ids[ordinal]
                if ordinal < len(configured_ids)
                else f"ORG-{_normalize_token(actor_class)}-{ordinal + 1:04d}"
            )
            rows.append(
                _actor_row(
                    ctx,
                    actor_class=actor_class,
                    organization_id=organization_id,
                    region_id=region_id,
                    ordinal_parts={"ordinal": ordinal},
                )
            )

    actor_ids = [row["actor_id"] for row in rows]
    if len(actor_ids) != len(set(actor_ids)):
        raise WorldBuildError(f"{ctx.scenario_id}: duplicate actor_id generated")
    return tuple(sorted(rows, key=lambda row: (row["actor_class"], row["region_id"], row["actor_id"])))


def _actors_by_class(actors: Iterable[Mapping[str, Any]]) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for actor in actors:
        grouped.setdefault(str(actor["actor_class"]), []).append(actor)
    return {key: tuple(sorted(values, key=lambda row: row["actor_id"])) for key, values in grouped.items()}


def _actor_for_region(
    actors: tuple[dict[str, Any], ...],
    *,
    actor_classes: tuple[str, ...],
    region_id: str,
) -> Mapping[str, Any]:
    candidates = [
        actor
        for actor in actors
        if actor["actor_class"] in actor_classes and actor["region_id"] == region_id
    ]
    if not candidates:
        candidates = [actor for actor in actors if actor["actor_class"] in actor_classes]
    if not candidates:
        raise WorldBuildError(
            f"no actor found for classes {actor_classes} in or near region {region_id}"
        )
    return sorted(candidates, key=lambda row: row["actor_id"])[0]


def _build_network_areas(
    ctx: _WorldContext,
    actors: tuple[dict[str, Any], ...],
    cohorts: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    region_counts = _represented_counts_by_region(cohorts)
    rows: list[dict[str, Any]] = []
    for region_id in sorted(ctx.resolved.world.regions):
        total = region_counts.get(region_id, 0)
        if total <= 0:
            raise WorldBuildError(f"{ctx.scenario_id}: region {region_id} has no represented network exposure")
        prosumer_count = sum(
            int(cohort["represented_prosumer_count"])
            for cohort in cohorts
            if cohort["region_id"] == region_id
        )
        consumer_count = total - prosumer_count
        controller = _actor_for_region(actors, actor_classes=("dso", "tso"), region_id=region_id)
        operator = _actor_for_region(
            actors,
            actor_classes=("dso", "tso", "supplier", "aggregator", "processor"),
            region_id=region_id,
        )
        area_id = deterministic_uuid(
            ctx.namespace,
            "network_area",
            {
                "scenario_id": ctx.scenario_id,
                "region_id": region_id,
                "network_area_kind": "substation_area",
            },
        )
        row = {
            "network_area_id": area_id,
            "scenario_id": ctx.scenario_id,
            "region_id": region_id,
            "jurisdiction_id": _jurisdiction_for_region(ctx, region_id),
            "network_area_kind": "substation_area",
            "parent_network_area_id": None,
            "controller_actor_id": controller["actor_id"],
            "operator_actor_id": operator["actor_id"],
            "fault_domain_id": _fault_domain_for_region(ctx, region_id),
            "trust_domain_id": controller["trust_domain_id"],
            "represented_consumer_count": consumer_count,
            "represented_prosumer_count": prosumer_count,
            "valid_from": ctx.resolved.run.horizon_start,
            "valid_to": ctx.resolved.run.horizon_end,
            "source_profile_id": ctx.resolved.physical.calibration_bundle_id,
            "generation_source": "controlled_synthetic",
        }
        validate_record(ctx.contract, "network_area", row)
        rows.append(row)
    return tuple(sorted(rows, key=lambda row: row["network_area_id"]))


def _candidate_relationship_pairs(
    actors: tuple[dict[str, Any], ...],
    relationship_type: str,
) -> tuple[tuple[Mapping[str, Any], Mapping[str, Any]], ...]:
    source_classes, target_classes = RELATIONSHIP_RULES[relationship_type]
    by_class = _actors_by_class(actors)
    sources = tuple(actor for cls in source_classes for actor in by_class.get(cls, ()))
    targets = tuple(actor for cls in target_classes for actor in by_class.get(cls, ()))
    pairs = [
        (source, target)
        for source in sources
        for target in targets
        if source["actor_id"] != target["actor_id"]
    ]
    return tuple(pairs)


def _build_relationships(
    ctx: _WorldContext,
    actors: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    allowed_relationships = set(ctx.contract.dictionary_values("relationship_type"))
    configured_counts = _relationship_count_map(ctx.resolved)
    for relationship_type, count in configured_counts.items():
        if relationship_type not in allowed_relationships:
            raise WorldBuildError(f"{ctx.scenario_id}: unknown relationship_type {relationship_type!r}")
        if relationship_type not in RELATIONSHIP_RULES:
            raise WorldBuildError(f"{ctx.scenario_id}: no role constraints for {relationship_type!r}")
        candidates = _candidate_relationship_pairs(actors, relationship_type)
        ranked = sorted(
            candidates,
            key=lambda pair: _stable_score(
                ctx.namespace,
                f"relationship:{relationship_type}",
                {
                    "source_actor_id": pair[0]["actor_id"],
                    "target_actor_id": pair[1]["actor_id"],
                },
            ),
        )
        if count > len(ranked):
            raise WorldBuildError(
                f"{ctx.scenario_id}: requested {count} {relationship_type} relationships "
                f"but only {len(ranked)} valid actor pairs exist"
            )
        for ordinal, (source, target) in enumerate(ranked[:count]):
            relationship_id = deterministic_uuid(
                ctx.namespace,
                "actor_relationship",
                {
                    "relationship_type": relationship_type,
                    "source_actor_id": source["actor_id"],
                    "target_actor_id": target["actor_id"],
                    "scenario_id": ctx.scenario_id,
                },
            )
            row = {
                "relationship_id": relationship_id,
                "scenario_id": ctx.scenario_id,
                "source_actor_id": source["actor_id"],
                "target_actor_id": target["actor_id"],
                "relationship_type": relationship_type,
                "contract_id": f"REL-{_normalize_token(relationship_type)}-{ordinal + 1:06d}",
                "policy_profile_id": ctx.resolved.policy.profile_id,
                "valid_from": ctx.resolved.run.horizon_start,
                "valid_to": ctx.resolved.run.horizon_end,
            }
            validate_record(ctx.contract, "actor_relationship", row)
            rows.append(row)
    relationship_ids = [row["relationship_id"] for row in rows]
    if len(relationship_ids) != len(set(relationship_ids)):
        raise WorldBuildError(f"{ctx.scenario_id}: duplicate relationship_id generated")
    return tuple(sorted(rows, key=lambda row: (row["relationship_type"], row["relationship_id"])))


def _relationship_counts(rows: Iterable[Mapping[str, Any]]) -> Mapping[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["relationship_type"])] = counts.get(str(row["relationship_type"]), 0) + 1
    return dict(sorted(counts.items()))


def _actor_counts(rows: Iterable[Mapping[str, Any]]) -> Mapping[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["actor_class"])] = counts.get(str(row["actor_class"]), 0) + 1
    return dict(sorted(counts.items()))


def _represented_counts_by_region(rows: Iterable[Mapping[str, Any]]) -> Mapping[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        region_id = str(row["region_id"])
        counts[region_id] = counts.get(region_id, 0) + int(row["represented_consumer_count"]) + int(row["represented_prosumer_count"])
    return dict(sorted(counts.items()))


def _diagnostics(
    resolved: ResolvedConfig,
    scenario_id: str,
    actors: tuple[dict[str, Any], ...],
    relationships: tuple[dict[str, Any], ...],
    cohorts: tuple[dict[str, Any], ...],
    network_areas: tuple[dict[str, Any], ...],
) -> TopologyDiagnostics:
    controller_count = sum(1 for actor in actors if "controller" in actor["capabilities"])
    max_controller_population = (
        ceil(resolved.claim_scale.represented_population / controller_count)
        if controller_count
        else resolved.claim_scale.represented_population
    )
    return TopologyDiagnostics(
        scenario_id=scenario_id,
        represented_population=resolved.claim_scale.represented_population,
        materialized_actor_count=len(actors),
        materialized_network_area_count=len(network_areas),
        materialized_cohort_count=len(cohorts),
        actor_counts_by_class=_actor_counts(actors),
        relationship_counts_by_type=_relationship_counts(relationships),
        represented_counts_by_region=_represented_counts_by_region(cohorts),
        controller_actor_count=controller_count,
        max_controller_represented_population=max_controller_population,
    )


def build_federated_world(
    resolved: ResolvedConfig,
    *,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> FederatedWorld:
    """Build schema-valid federated world rows for selected scenarios."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise WorldBuildError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise WorldBuildError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise WorldBuildError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )

    all_actors: list[dict[str, Any]] = []
    all_relationships: list[dict[str, Any]] = []
    all_cohorts: list[dict[str, Any]] = []
    all_network_areas: list[dict[str, Any]] = []
    diagnostics: dict[str, TopologyDiagnostics] = {}

    for scenario_id in sorted(selected):
        ctx = _world_context(resolved, scenario_id, replicate_id, schema_contract)
        cohorts = _build_cohorts(ctx)
        actors = _build_actors(ctx, cohorts)
        network_areas = _build_network_areas(ctx, actors, cohorts)
        relationships = _build_relationships(ctx, actors)
        world = FederatedWorld(
            actors=actors,
            actor_relationships=relationships,
            prosumer_cohorts=cohorts,
            network_areas=network_areas,
            diagnostics={
                scenario_id: _diagnostics(
                    resolved,
                    scenario_id,
                    actors,
                    relationships,
                    cohorts,
                    network_areas,
                )
            },
        )
        validate_federated_world(world, resolved, contract=schema_contract, scenario_ids=(scenario_id,))
        all_actors.extend(actors)
        all_relationships.extend(relationships)
        all_cohorts.extend(cohorts)
        all_network_areas.extend(network_areas)
        diagnostics[scenario_id] = world.diagnostics[scenario_id]

    return FederatedWorld(
        actors=tuple(sorted(all_actors, key=lambda row: (row["scenario_id"], row["actor_id"]))),
        actor_relationships=tuple(sorted(all_relationships, key=lambda row: (row["scenario_id"], row["relationship_id"]))),
        prosumer_cohorts=tuple(sorted(all_cohorts, key=lambda row: (row["scenario_id"], row["cohort_id"]))),
        network_areas=tuple(sorted(all_network_areas, key=lambda row: (row["scenario_id"], row["network_area_id"]))),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def _validate_temporal_interval(
    row: Mapping[str, Any],
    *,
    table_name: str,
    identifier_field: str,
) -> None:
    valid_from = _timestamp(str(row["valid_from"]))
    valid_to_raw = row.get("valid_to")
    if valid_to_raw is not None and _timestamp(str(valid_to_raw)) < valid_from:
        raise WorldBuildError(
            f"{table_name} {row[identifier_field]} has valid_to earlier than valid_from"
        )


def _validate_relationship_roles(
    relationship: Mapping[str, Any],
    actor_by_id: Mapping[str, Mapping[str, Any]],
) -> None:
    relationship_type = str(relationship["relationship_type"])
    if relationship_type not in RELATIONSHIP_RULES:
        raise WorldBuildError(f"relationship {relationship['relationship_id']}: unsupported type {relationship_type!r}")
    source_classes, target_classes = RELATIONSHIP_RULES[relationship_type]
    try:
        source = actor_by_id[str(relationship["source_actor_id"])]
        target = actor_by_id[str(relationship["target_actor_id"])]
    except KeyError as exc:
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: unresolved actor FK {exc}"
        ) from exc
    if source["actor_class"] not in source_classes:
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: source actor class "
            f"{source['actor_class']!r} invalid for {relationship_type}"
        )
    if target["actor_class"] not in target_classes:
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: target actor class "
            f"{target['actor_class']!r} invalid for {relationship_type}"
        )
    source_from = _timestamp(str(source["valid_from"]))
    rel_from = _timestamp(str(relationship["valid_from"]))
    if rel_from < source_from:
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: starts before source actor validity"
        )
    source_to = source.get("valid_to")
    rel_to = relationship.get("valid_to")
    if source_to is not None and rel_to is not None and _timestamp(str(rel_to)) > _timestamp(str(source_to)):
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: ends after source actor validity"
        )
    target_from = _timestamp(str(target["valid_from"]))
    if rel_from < target_from:
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: starts before target actor validity"
        )
    target_to = target.get("valid_to")
    if target_to is not None and rel_to is not None and _timestamp(str(rel_to)) > _timestamp(str(target_to)):
        raise WorldBuildError(
            f"relationship {relationship['relationship_id']}: ends after target actor validity"
        )


def _validate_region_actor_distribution(
    resolved: ResolvedConfig,
    actors: tuple[Mapping[str, Any], ...],
    scenario_id: str,
) -> None:
    regions = tuple(resolved.world.regions)
    for actor_class in INSTITUTIONAL_CLASSES:
        class_rows = [row for row in actors if row["actor_class"] == actor_class]
        if not class_rows:
            raise WorldBuildError(f"{scenario_id}: missing institutional actor class {actor_class}")
        if len(class_rows) >= len(regions):
            covered_regions = {str(row["region_id"]) for row in class_rows}
            if set(regions) - covered_regions:
                raise WorldBuildError(
                    f"{scenario_id}: actor class {actor_class} does not cover all configured regions"
                )


def validate_federated_world(
    world: FederatedWorld,
    resolved: ResolvedConfig,
    *,
    contract: ContractSpec | None = None,
    scenario_ids: Iterable[str] | None = None,
) -> None:
    """Fail closed on schema, topology, reconciliation, and role violations."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    actor_by_id = {row["actor_id"]: row for row in world.actors}
    if len(actor_by_id) != len(world.actors):
        raise WorldBuildError("duplicate actor_id values in world")
    relationship_ids = [row["relationship_id"] for row in world.actor_relationships]
    if len(relationship_ids) != len(set(relationship_ids)):
        raise WorldBuildError("duplicate relationship_id values in world")
    cohort_ids = [(row["scenario_id"], row["cohort_id"]) for row in world.prosumer_cohorts]
    if len(cohort_ids) != len(set(cohort_ids)):
        raise WorldBuildError("duplicate cohort_id values in world")
    network_area_ids = [
        (row["scenario_id"], row["network_area_id"]) for row in world.network_areas
    ]
    if len(network_area_ids) != len(set(network_area_ids)):
        raise WorldBuildError("duplicate network_area_id values in world")

    for row in world.actors:
        validate_record(schema_contract, "actor", row)
        _validate_temporal_interval(row, table_name="actor", identifier_field="actor_id")
    for row in world.network_areas:
        validate_record(schema_contract, "network_area", row)
        _validate_temporal_interval(row, table_name="network_area", identifier_field="network_area_id")
        if row["controller_actor_id"] not in actor_by_id:
            raise WorldBuildError(f"network_area {row['network_area_id']}: unresolved controller actor")
        if row["operator_actor_id"] is not None and row["operator_actor_id"] not in actor_by_id:
            raise WorldBuildError(f"network_area {row['network_area_id']}: unresolved operator actor")
        if int(row["represented_consumer_count"]) < 0 or int(row["represented_prosumer_count"]) < 0:
            raise WorldBuildError(f"network_area {row['network_area_id']}: represented counts must be non-negative")
    for row in world.prosumer_cohorts:
        validate_record(schema_contract, "prosumer_cohort", row)
        if int(row["represented_consumer_count"]) < 0 or int(row["represented_prosumer_count"]) < 0:
            raise WorldBuildError(f"cohort {row['cohort_id']}: represented counts must be non-negative")
        if not 0 <= float(row["der_adoption_fraction"]) <= 1:
            raise WorldBuildError(f"cohort {row['cohort_id']}: DER adoption fraction outside [0, 1]")
    for row in world.actor_relationships:
        validate_record(schema_contract, "actor_relationship", row)
        _validate_temporal_interval(row, table_name="actor_relationship", identifier_field="relationship_id")
        _validate_relationship_roles(row, actor_by_id)

    for scenario_id in selected:
        scenario_actors = tuple(row for row in world.actors if row["scenario_id"] == scenario_id)
        scenario_relationships = tuple(row for row in world.actor_relationships if row["scenario_id"] == scenario_id)
        scenario_cohorts = tuple(row for row in world.prosumer_cohorts if row["scenario_id"] == scenario_id)
        scenario_network_areas = tuple(row for row in world.network_areas if row["scenario_id"] == scenario_id)
        if not scenario_actors:
            raise WorldBuildError(f"{scenario_id}: no actors generated")
        if not scenario_cohorts:
            raise WorldBuildError(f"{scenario_id}: no cohorts generated")
        if not scenario_network_areas:
            raise WorldBuildError(f"{scenario_id}: no network areas generated")

        represented_total = sum(
            int(row["represented_consumer_count"]) + int(row["represented_prosumer_count"])
            for row in scenario_cohorts
        )
        if represented_total != resolved.claim_scale.represented_population:
            raise WorldBuildError(
                f"{scenario_id}: cohort total {represented_total} does not equal represented_population "
                f"{resolved.claim_scale.represented_population}"
            )

        configured_counts = _relationship_count_map(resolved)
        observed_counts = _relationship_counts(scenario_relationships)
        for relationship_type, expected in configured_counts.items():
            observed = observed_counts.get(relationship_type, 0)
            if observed != expected:
                raise WorldBuildError(
                    f"{scenario_id}: expected {expected} {relationship_type} relationships, observed {observed}"
                )

        region_counts = _represented_counts_by_region(scenario_cohorts)
        missing_regions = set(resolved.world.regions) - set(region_counts)
        if missing_regions:
            raise WorldBuildError(f"{scenario_id}: no represented cohort coverage for regions {sorted(missing_regions)}")
        if any(count <= 0 for count in region_counts.values()):
            raise WorldBuildError(f"{scenario_id}: every configured region must have positive represented count")
        network_regions = {str(row["region_id"]) for row in scenario_network_areas}
        if set(resolved.world.regions) - network_regions:
            raise WorldBuildError(
                f"{scenario_id}: no network-area coverage for regions {sorted(set(resolved.world.regions) - network_regions)}"
            )

        _validate_region_actor_distribution(resolved, scenario_actors, scenario_id)

        controller_count = sum(1 for actor in scenario_actors if "controller" in actor["capabilities"])
        if (
            resolved.claim_scale.represented_population >= SCALE_CONTROLLER_THRESHOLD
            and controller_count <= 1
            and "analytic_aggregation" not in resolved.claim_scale.aggregation_semantics
        ):
            raise WorldBuildError(
                f"{scenario_id}: represented population {resolved.claim_scale.represented_population} "
                "cannot be assigned to one logical controller without explicit analytic aggregation"
            )
