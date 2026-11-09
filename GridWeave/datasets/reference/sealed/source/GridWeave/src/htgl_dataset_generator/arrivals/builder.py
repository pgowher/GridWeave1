"""S05 exact hierarchical arrivals and conditional marks.

This module implements the arrival process specified by Dataset-2:

``lambda_{r,f}(t) = N_r * a_f * s_{r,f} * d_f(t) * w_f(t) * x_{r,f}(t)``.

It intentionally avoids rounded-Gaussian count approximations, uniform-bin
NHPP timestamps for non-constant intensity, global RNG state, UUID4, wall-clock
time, and independent mark draws.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import exp, isfinite, log, sqrt
from typing import Any, Iterable, Mapping, Sequence
import json

from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.physical import GovernanceTrigger, PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, deterministic_uuid, seed_stream_records_for_plan
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


ARRIVAL_COMPONENT = "S05.arrivals"
SECONDS_PER_DAY = 86_400.0
EPSILON = 1e-12
MAX_EXACT_POISSON_EXPECTATION = 250_000.0

SUBJECT_EVENT_FAMILIES = frozenset(
    {
        "consent",
        "collection_processing",
        "disclosure",
        "access",
        "correction",
        "retention",
        "erasure",
        "operational",
        "notification",
    }
)

EVENT_OBJECT_TYPES: Mapping[str, tuple[str, ...]] = {
    "consent": ("consent", "profile"),
    "collection_processing": ("meter_interval", "profile", "model_feature"),
    "disclosure": ("profile", "meter_interval", "audit_record"),
    "access": ("profile", "bill", "meter_interval"),
    "correction": ("meter_interval", "profile", "bill"),
    "retention": ("audit_record", "evidence_record", "meter_interval"),
    "erasure": ("consent", "meter_interval", "profile"),
    "operational": ("operational_command", "market_bid", "meter_interval"),
    "audit": ("audit_record", "evidence_record"),
    "incident": ("operational_command", "audit_record", "meter_interval"),
    "notification": ("consent", "profile", "bill"),
}

EVENT_ROLE_CLASSES: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "consent": {
        "requesting": ("consumer", "prosumer"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor", "oversight", "validator"),
    },
    "collection_processing": {
        "requesting": ("dso", "supplier", "processor"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor"),
    },
    "disclosure": {
        "requesting": ("supplier", "aggregator", "processor", "vendor", "regulator", "auditor"),
        "source": ("dso", "supplier", "aggregator"),
        "oversight": ("regulator", "auditor", "oversight"),
    },
    "access": {
        "requesting": ("consumer", "prosumer", "auditor", "regulator"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor"),
    },
    "correction": {
        "requesting": ("consumer", "prosumer"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor"),
    },
    "retention": {
        "requesting": ("dso", "supplier", "auditor", "regulator"),
        "source": ("dso", "supplier", "processor"),
        "oversight": ("regulator", "auditor"),
    },
    "erasure": {
        "requesting": ("consumer", "prosumer", "regulator"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor"),
    },
    "operational": {
        "requesting": ("dso", "tso", "aggregator", "processor"),
        "source": ("dso", "tso", "aggregator"),
        "oversight": ("regulator", "auditor"),
    },
    "audit": {
        "requesting": ("auditor", "regulator"),
        "source": ("dso", "supplier", "aggregator", "processor", "vendor"),
        "oversight": ("regulator", "auditor", "oversight"),
    },
    "incident": {
        "requesting": ("dso", "tso", "regulator"),
        "source": ("dso", "tso", "aggregator"),
        "oversight": ("regulator", "auditor", "oversight"),
    },
    "notification": {
        "requesting": ("dso", "supplier", "regulator"),
        "source": ("consumer", "prosumer"),
        "oversight": ("regulator", "auditor"),
    },
}

PURPOSE_BY_EVENT: Mapping[str, tuple[str, ...]] = {
    "consent": ("consent_management", "rights_management"),
    "collection_processing": ("metering", "billing", "grid_operations"),
    "disclosure": ("oversight", "analytics", "forecasting", "audit"),
    "access": ("rights_management", "billing", "analytics", "customer_accounting"),
    "correction": ("rights_management", "billing", "metering"),
    "retention": ("audit", "evidence", "oversight"),
    "erasure": ("rights_management", "consent_management"),
    "operational": ("grid_operations", "der_dispatch", "market_operations"),
    "audit": ("audit", "oversight", "evidence"),
    "incident": ("grid_operations", "audit", "oversight"),
    "notification": ("customer_accounting", "rights_management", "consent_management"),
}


class ArrivalGenerationError(ValueError):
    """Raised when S05 arrivals cannot satisfy the Dataset-2 contract."""


@dataclass(frozen=True)
class ArrivalIntensityBin:
    scenario_id: str
    replicate_id: int
    region_id: str
    event_family: str
    bin_index: int
    bin_start: str
    bin_end: str
    integrated_intensity: float
    model_class: str
    intensity_start_factor: float
    intensity_end_factor: float
    integrated_exposure: float
    regime_id: str | None = None


@dataclass(frozen=True)
class ArrivalMark:
    arrival_id: str
    source_actor_id: str
    requesting_actor_id: str
    controller_actor_id: str
    processor_actor_id: str
    oversight_actor_id: str
    local_database_id: str
    data_object_id: str
    purpose_tag: str
    jurisdiction_id: str
    workflow_profile_id: str
    structural_path: tuple[str, ...]
    trigger_id: str | None = None


@dataclass(frozen=True)
class ArrivalDiagnostics:
    scenario_id: str
    replicate_id: int
    model_class: str
    expected_count: float
    observed_count: int
    count_mean_ratio: float
    dispersion_index: float
    bin_deviance: float
    time_rescaling_ks: float
    interarrival_distance: float
    cross_excitation_error: float
    regime_occupancy_error: float
    passed: bool


@dataclass(frozen=True)
class ArrivalBuild:
    arrivals: tuple[dict[str, Any], ...]
    marks: tuple[ArrivalMark, ...]
    intensity_bins: tuple[ArrivalIntensityBin, ...]
    diagnostics: Mapping[str, ArrivalDiagnostics]

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"arrival": self.arrivals}


@dataclass(frozen=True)
class _ArrivalContext:
    resolved: ResolvedConfig
    scenario_id: str
    replicate_id: int
    model_class: str
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    world: FederatedWorld
    catalog: CatalogBuild
    physical: PhysicalRawBuild


@dataclass(frozen=True)
class _RegimeInterval:
    regime_id: str
    state: str
    start: datetime
    end: datetime
    multiplier: float


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stable_region_family_scale(region_id: str, event_family: str) -> float:
    payload = json.dumps({"family": event_family, "region": region_id}, sort_keys=True, separators=(",", ":"))
    bucket = sum(payload.encode("utf-8")) % 17
    return 0.92 + (bucket / 16.0) * 0.16


def _diurnal_factor(event_family: str, when: datetime) -> float:
    hour = when.hour + when.minute / 60.0 + when.second / 3600.0
    if event_family in {"incident", "operational"}:
        return 0.82 + 0.24 * _smooth_peak(hour, 17.5, 5.5)
    if event_family in {"audit", "retention"}:
        return 0.20 + 1.75 * _business_hours_shape(hour)
    if event_family in {"collection_processing"}:
        return 0.80 + 0.35 * _smooth_peak(hour, 1.0, 6.0)
    if event_family in {"consent", "access", "correction", "erasure", "disclosure", "notification"}:
        return 0.28 + 1.55 * _business_hours_shape(hour) + 0.30 * _smooth_peak(hour, 20.0, 3.5)
    return 1.0


def _business_hours_shape(hour: float) -> float:
    morning = _smooth_peak(hour, 10.5, 2.8)
    afternoon = _smooth_peak(hour, 15.0, 3.0)
    return max(0.0, min(1.7, morning + afternoon))


def _smooth_peak(hour: float, center: float, width: float) -> float:
    distance = abs(hour - center)
    distance = min(distance, 24.0 - distance)
    return exp(-0.5 * (distance / width) ** 2)


def _weekday_factor(event_family: str, when: datetime) -> float:
    if when.weekday() < 5:
        return 1.0
    if event_family in {"incident", "operational"}:
        return 0.95
    return 0.58


def _scenario_factor(resolved: ResolvedConfig, event_family: str) -> float:
    factors = resolved.arrivals.scenario_factors
    base = float(factors.get("normal", 1.0))
    if event_family in {"incident", "operational"}:
        return max(base, float(factors.get("outage", base)))
    return base


def _region_counts(world: FederatedWorld, scenario_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for cohort in world.prosumer_cohorts:
        if cohort["scenario_id"] != scenario_id:
            continue
        region_id = str(cohort["region_id"])
        counts[region_id] = counts.get(region_id, 0) + int(cohort["represented_consumer_count"]) + int(
            cohort["represented_prosumer_count"]
        )
    return counts


def _trigger_index(
    physical: PhysicalRawBuild,
    *,
    scenario_id: str,
    start: datetime,
    interval_seconds: int,
) -> dict[tuple[str, str, int], tuple[GovernanceTrigger, ...]]:
    index: dict[tuple[str, str, int], list[GovernanceTrigger]] = {}
    for trigger in physical.governance_triggers:
        if trigger.scenario_id != scenario_id:
            continue
        trigger_time = _timestamp(trigger.timestamp)
        bin_index = int((trigger_time - start).total_seconds() // interval_seconds)
        key = (trigger.region_id, trigger.event_family, bin_index)
        index.setdefault(key, []).append(trigger)
    return {key: tuple(sorted(values, key=lambda item: item.trigger_id)) for key, values in index.items()}


def _trigger_factor(trigger_count: int) -> float:
    if trigger_count <= 0:
        return 1.0
    return 1.0 + min(2.5, 0.22 * trigger_count)


def _build_base_intensity_bins(ctx: _ArrivalContext) -> tuple[ArrivalIntensityBin, ...]:
    start = _timestamp(ctx.resolved.run.horizon_start)
    end = _timestamp(ctx.resolved.run.horizon_end)
    interval_seconds = ctx.resolved.physical.interval_seconds
    if interval_seconds <= 0:
        raise ArrivalGenerationError("physical.interval_seconds must be positive")
    if end <= start:
        raise ArrivalGenerationError("run.horizon_end must be later than run.horizon_start")

    region_counts = _region_counts(ctx.world, ctx.scenario_id)
    configured_regions = set(ctx.resolved.world.regions)
    if set(region_counts) != configured_regions:
        raise ArrivalGenerationError(
            f"{ctx.scenario_id}: cohort represented counts do not cover configured regions"
        )
    trigger_by_key = _trigger_index(
        ctx.physical,
        scenario_id=ctx.scenario_id,
        start=start,
        interval_seconds=interval_seconds,
    )

    rows: list[ArrivalIntensityBin] = []
    bin_count = int((end - start).total_seconds() // interval_seconds)
    if start + timedelta(seconds=bin_count * interval_seconds) != end:
        raise ArrivalGenerationError("horizon must be an integer multiple of physical.interval_seconds")
    for bin_index in range(bin_count):
        bin_start = start + timedelta(seconds=bin_index * interval_seconds)
        bin_end = bin_start + timedelta(seconds=interval_seconds)
        midpoint = bin_start + (bin_end - bin_start) / 2
        for region_id in sorted(region_counts):
            n_region = region_counts[region_id]
            for event_family in sorted(ctx.resolved.arrivals.base_rates_per_day):
                rate_per_day = float(ctx.resolved.arrivals.base_rates_per_day[event_family])
                if rate_per_day < 0:
                    raise ArrivalGenerationError(f"negative base rate for event_family={event_family}")
                start_factor = (
                    _stable_region_family_scale(region_id, event_family)
                    * _diurnal_factor(event_family, bin_start)
                    * _weekday_factor(event_family, bin_start)
                    * _scenario_factor(ctx.resolved, event_family)
                    * _trigger_factor(len(trigger_by_key.get((region_id, event_family, bin_index), ())))
                )
                end_factor = (
                    _stable_region_family_scale(region_id, event_family)
                    * _diurnal_factor(event_family, bin_end)
                    * _weekday_factor(event_family, bin_end)
                    * _scenario_factor(ctx.resolved, event_family)
                    * _trigger_factor(len(trigger_by_key.get((region_id, event_family, bin_index), ())))
                )
                mid_factor = (
                    _stable_region_family_scale(region_id, event_family)
                    * _diurnal_factor(event_family, midpoint)
                    * _weekday_factor(event_family, midpoint)
                    * _scenario_factor(ctx.resolved, event_family)
                    * _trigger_factor(len(trigger_by_key.get((region_id, event_family, bin_index), ())))
                )
                integrated = n_region * rate_per_day * mid_factor * (interval_seconds / SECONDS_PER_DAY)
                rows.append(
                    ArrivalIntensityBin(
                        scenario_id=ctx.scenario_id,
                        replicate_id=ctx.replicate_id,
                        region_id=region_id,
                        event_family=event_family,
                        bin_index=bin_index,
                        bin_start=_format_timestamp(bin_start),
                        bin_end=_format_timestamp(bin_end),
                        integrated_intensity=max(0.0, integrated),
                        model_class=ctx.model_class,
                        intensity_start_factor=max(EPSILON, start_factor),
                        intensity_end_factor=max(EPSILON, end_factor),
                        integrated_exposure=float(n_region) * (interval_seconds / SECONDS_PER_DAY),
                        regime_id=None,
                    )
                )
    return tuple(rows)


def _weighted_choice(
    rng: CounterRng,
    label: str,
    index: int,
    items: Sequence[Any],
    weights: Sequence[float],
) -> Any:
    if len(items) != len(weights):
        raise ArrivalGenerationError("weighted choice items and weights length mismatch")
    if not items:
        raise ArrivalGenerationError(f"{label}: no eligible choices")
    total = sum(float(weight) for weight in weights)
    if not isfinite(total) or total <= 0:
        raise ArrivalGenerationError(f"{label}: weights must sum to a positive finite value")
    cut = rng.uniform(label, index) * total
    cumulative = 0.0
    for item, weight in zip(items, weights):
        cumulative += float(weight)
        if cut <= cumulative:
            return item
    return items[-1]


def _poisson_exact(rng: CounterRng, label: str, lambda_value: float, index: int) -> int:
    if lambda_value < 0 or not isfinite(lambda_value):
        raise ArrivalGenerationError(f"{label}: Poisson intensity must be finite and non-negative")
    if lambda_value == 0:
        return 0
    if lambda_value > MAX_EXACT_POISSON_EXPECTATION:
        raise ArrivalGenerationError(
            f"{label}: exact Poisson expectation {lambda_value:.3f} exceeds "
            f"{MAX_EXACT_POISSON_EXPECTATION:.0f}; use conditioned-exact materialization or reduce n"
        )
    count = 0
    elapsed = 0.0
    draw_index = 0
    while True:
        uniform = max(EPSILON, rng.uniform(f"{label}:poisson-wait", index * 1_000_003 + draw_index))
        elapsed += -log(uniform)
        if elapsed > lambda_value:
            return count
        count += 1
        draw_index += 1


def _multinomial_exact(
    rng: CounterRng,
    label: str,
    total_count: int,
    weights: Sequence[float],
) -> tuple[int, ...]:
    if total_count < 0:
        raise ArrivalGenerationError("conditioned_total must be non-negative")
    total_weight = sum(float(weight) for weight in weights)
    if total_count > 0 and total_weight <= 0:
        raise ArrivalGenerationError("conditioned-exact allocation requires positive integrated intensity")
    if total_count == 0:
        return tuple(0 for _ in weights)
    cumulative: list[float] = []
    running = 0.0
    for weight in weights:
        running += float(weight) / total_weight
        cumulative.append(running)
    counts = [0 for _ in weights]
    for draw_index in range(total_count):
        u = rng.uniform(f"{label}:multinomial", draw_index)
        bucket = bisect_left(cumulative, u)
        counts[min(bucket, len(counts) - 1)] += 1
    return tuple(counts)


def _sample_within_bin(ctx: _ArrivalContext, bin_row: ArrivalIntensityBin, ordinal: int) -> str:
    start = _timestamp(bin_row.bin_start)
    end = _timestamp(bin_row.bin_end)
    duration = (end - start).total_seconds()
    y0 = max(EPSILON, bin_row.intensity_start_factor)
    y1 = max(EPSILON, bin_row.intensity_end_factor)
    u = ctx.rng.uniform("arrival-timestamp-inversion", ordinal)
    if abs(y1 - y0) <= 1e-10:
        fraction = u
    else:
        slope = y1 - y0
        # Solve y0*x + 0.5*slope*x^2 = u * (y0 + y1) / 2 for x in [0, 1].
        target = u * (y0 + y1) / 2.0
        discriminant = max(0.0, y0 * y0 + 2.0 * slope * target)
        fraction = (-y0 + sqrt(discriminant)) / slope
        fraction = max(0.0, min(1.0, fraction))
    return _format_timestamp(start + timedelta(seconds=duration * fraction))


def _generate_nhpp_arrivals(
    ctx: _ArrivalContext,
    bins: tuple[ArrivalIntensityBin, ...],
) -> tuple[tuple[dict[str, Any], ...], tuple[ArrivalMark, ...], tuple[int, ...]]:
    expected_total = sum(bin_row.integrated_intensity for bin_row in bins)
    if ctx.model_class == "conditioned_NHPP" and ctx.resolved.arrivals.conditioned_total is None:
        raise ArrivalGenerationError("conditioned_NHPP requires arrivals.conditioned_total")
    if ctx.model_class in {"conditioned_NHPP", "MMPP"} and ctx.resolved.arrivals.conditioned_total is not None:
        total_count = int(ctx.resolved.arrivals.conditioned_total)
        if total_count > ctx.resolved.claim_scale.materialized_row_target:
            raise ArrivalGenerationError(
                "conditioned_total exceeds claim_scale.materialized_row_target; N/n separation would be violated"
            )
        counts = _multinomial_exact(
            ctx.rng,
            f"{ctx.scenario_id}:{ctx.replicate_id}:conditioned",
            total_count,
            [bin_row.integrated_intensity for bin_row in bins],
        )
        represented_weight = expected_total / total_count if total_count else 0.0
    elif ctx.model_class in {"unconditioned_NHPP", "MMPP"}:
        if expected_total > ctx.resolved.claim_scale.materialized_row_target:
            raise ArrivalGenerationError(
                f"unconditioned_NHPP expected materialized count {expected_total:.3f} exceeds "
                f"materialized_row_target={ctx.resolved.claim_scale.materialized_row_target}; "
                "use conditioned_NHPP for represented-population studies"
            )
        counts = tuple(
            _poisson_exact(
                ctx.rng,
                f"{ctx.scenario_id}:{bin_row.region_id}:{bin_row.event_family}:{bin_row.bin_index}",
                bin_row.integrated_intensity,
                index,
            )
            for index, bin_row in enumerate(bins)
        )
        represented_weight = 1.0
    else:
        raise ArrivalGenerationError(f"_generate_nhpp_arrivals received unsupported mode {ctx.model_class}")

    arrivals: list[dict[str, Any]] = []
    marks: list[ArrivalMark] = []
    global_ordinal = 0
    for bin_ordinal, (bin_row, count) in enumerate(zip(bins, counts)):
        for within_count in range(count):
            timestamp = _sample_within_bin(ctx, bin_row, global_ordinal)
            arrival_id = deterministic_uuid(
                ctx.namespace,
                "arrival",
                {
                    "bin": bin_row.bin_index,
                    "family": bin_row.event_family,
                    "model_class": ctx.model_class,
                    "ordinal": within_count,
                    "region": bin_row.region_id,
                    "replicate_id": ctx.replicate_id,
                    "scenario_id": ctx.scenario_id,
                },
            )
            row = {
                "arrival_id": arrival_id,
                "scenario_id": ctx.scenario_id,
                "replicate_id": ctx.replicate_id,
                "timestamp": timestamp,
                "arrival_bin": bin_row.bin_index,
                "event_family": bin_row.event_family,
                "region_id": bin_row.region_id,
                "subject_cohort_id": None,
                "model_class": ctx.model_class,
                "intensity_per_second": bin_row.integrated_intensity
                / max(EPSILON, (_timestamp(bin_row.bin_end) - _timestamp(bin_row.bin_start)).total_seconds()),
                "regime_id": bin_row.regime_id,
                "parent_arrival_id": None,
                "anomaly_designated": False,
                "represented_arrival_count": float(represented_weight),
            }
            mark = _conditional_mark(ctx, row, global_ordinal)
            row["subject_cohort_id"] = _subject_cohort_from_mark(mark, ctx)
            arrivals.append(row)
            marks.append(mark)
            global_ordinal += 1
    return tuple(arrivals), tuple(marks), counts


def _subject_cohort_from_mark(mark: ArrivalMark, ctx: _ArrivalContext) -> str | None:
    database = _database_by_id(ctx)[mark.local_database_id]
    data_object = _object_by_id(ctx)[mark.data_object_id]
    if data_object.get("subject_cohort_id") is not None:
        return str(data_object["subject_cohort_id"])
    if str(database["database_kind"]) in {"audit", "archive"}:
        return None
    return None


def _database_by_id(ctx: _ArrivalContext) -> dict[str, dict[str, Any]]:
    return {str(row["database_id"]): row for row in ctx.catalog.local_databases if row["scenario_id"] == ctx.scenario_id}


def _object_by_id(ctx: _ArrivalContext) -> dict[str, dict[str, Any]]:
    return {str(row["data_object_id"]): row for row in ctx.catalog.data_objects if row["scenario_id"] == ctx.scenario_id}


def _actors_by_id(ctx: _ArrivalContext) -> dict[str, dict[str, Any]]:
    return {str(row["actor_id"]): row for row in ctx.world.actors if row["scenario_id"] == ctx.scenario_id}


def _cohorts_by_id(ctx: _ArrivalContext) -> dict[str, dict[str, Any]]:
    return {str(row["cohort_id"]): row for row in ctx.world.prosumer_cohorts if row["scenario_id"] == ctx.scenario_id}


def _conditional_mark(ctx: _ArrivalContext, arrival: Mapping[str, Any], ordinal: int) -> ArrivalMark:
    region_id = str(arrival["region_id"])
    event_family = str(arrival["event_family"])
    cohort = _choose_cohort(ctx, region_id, event_family, ordinal)
    data_object = _choose_object(ctx, region_id, event_family, cohort, ordinal)
    databases = _database_by_id(ctx)
    database = databases[str(data_object["origin_database_id"])]
    actors = _actors_by_id(ctx)
    controller = actors[str(database["controller_actor_id"])]
    processor = actors[str(database["operator_actor_id"])]
    requesting = _choose_actor(ctx, event_family, "requesting", region_id, ordinal)
    source = _choose_source_actor(ctx, event_family, cohort, region_id, ordinal)
    oversight = _choose_actor(ctx, event_family, "oversight", region_id, ordinal)
    purpose = _choose_purpose(ctx, event_family, data_object, ordinal)
    workflow_profile_id = ctx.resolved.workflows.definition_versions.get(event_family)
    if workflow_profile_id is None:
        raise ArrivalGenerationError(f"{ctx.scenario_id}: no workflow definition version for {event_family}")
    trigger = _matching_trigger(ctx, arrival, ordinal)

    mark = ArrivalMark(
        arrival_id=str(arrival["arrival_id"]),
        source_actor_id=str(source["actor_id"]),
        requesting_actor_id=str(requesting["actor_id"]),
        controller_actor_id=str(controller["actor_id"]),
        processor_actor_id=str(processor["actor_id"]),
        oversight_actor_id=str(oversight["actor_id"]),
        local_database_id=str(database["database_id"]),
        data_object_id=str(data_object["data_object_id"]),
        purpose_tag=purpose,
        jurisdiction_id=str(database.get("region_id") and controller["jurisdiction_id"]),
        workflow_profile_id=str(workflow_profile_id),
        structural_path=(
            f"region:{region_id}",
            f"cohort:{cohort['cohort_id'] if cohort is not None else 'none'}",
            f"requesting_actor_class:{requesting['actor_class']}",
            f"database:{database['database_kind']}",
            f"object:{data_object['object_type']}",
            f"purpose:{purpose}",
            f"jurisdiction:{controller['jurisdiction_id']}",
            f"workflow:{workflow_profile_id}",
        ),
        trigger_id=trigger.trigger_id if trigger is not None else None,
    )
    _validate_mark_constraints(ctx, arrival, mark)
    return mark


def _choose_cohort(
    ctx: _ArrivalContext,
    region_id: str,
    event_family: str,
    ordinal: int,
) -> Mapping[str, Any] | None:
    if event_family not in SUBJECT_EVENT_FAMILIES:
        return None
    cohorts = [
        row
        for row in ctx.world.prosumer_cohorts
        if row["scenario_id"] == ctx.scenario_id and row["region_id"] == region_id
    ]
    weights = [
        float(int(row["represented_consumer_count"]) + int(row["represented_prosumer_count"]))
        for row in cohorts
    ]
    return _weighted_choice(ctx.rng, f"mark:cohort:{region_id}:{event_family}", ordinal, cohorts, weights)


def _choose_object(
    ctx: _ArrivalContext,
    region_id: str,
    event_family: str,
    cohort: Mapping[str, Any] | None,
    ordinal: int,
) -> Mapping[str, Any]:
    databases = _database_by_id(ctx)
    allowed_types = EVENT_OBJECT_TYPES.get(event_family)
    if allowed_types is None:
        raise ArrivalGenerationError(f"no object-type mapping for event_family={event_family}")
    candidates: list[dict[str, Any]] = []
    for object_type in allowed_types:
        for data_object in ctx.catalog.data_objects:
            if data_object["scenario_id"] != ctx.scenario_id or data_object["object_type"] != object_type:
                continue
            database = databases[str(data_object["origin_database_id"])]
            if database["region_id"] != region_id:
                continue
            object_cohort = data_object.get("subject_cohort_id")
            if cohort is not None and object_cohort not in {None, cohort["cohort_id"]}:
                continue
            candidates.append(dict(data_object))
    if not candidates:
        raise ArrivalGenerationError(
            f"{ctx.scenario_id}: no data_object candidate for family={event_family}, region={region_id}"
        )
    weights = [4.0 if row["object_type"] == allowed_types[0] else 1.0 for row in candidates]
    return _weighted_choice(ctx.rng, f"mark:object:{region_id}:{event_family}", ordinal, candidates, weights)


def _choose_source_actor(
    ctx: _ArrivalContext,
    event_family: str,
    cohort: Mapping[str, Any] | None,
    region_id: str,
    ordinal: int,
) -> Mapping[str, Any]:
    if cohort is not None:
        subject_classes = set(EVENT_ROLE_CLASSES[event_family]["source"])
        subject_candidates = [
            row
            for row in ctx.world.actors
            if row["scenario_id"] == ctx.scenario_id
            and row["region_id"] == region_id
            and row["actor_class"] in subject_classes
        ]
        if subject_candidates:
            return _weighted_choice(
                ctx.rng,
                f"mark:source-subject:{region_id}:{event_family}",
                ordinal,
                subject_candidates,
                [1.0 for _ in subject_candidates],
            )
    return _choose_actor(ctx, event_family, "source", region_id, ordinal)


def _choose_actor(
    ctx: _ArrivalContext,
    event_family: str,
    role: str,
    region_id: str,
    ordinal: int,
) -> Mapping[str, Any]:
    role_classes = EVENT_ROLE_CLASSES.get(event_family, {}).get(role)
    if role_classes is None:
        raise ArrivalGenerationError(f"no actor role mapping for event_family={event_family}, role={role}")
    regional = [
        row
        for row in ctx.world.actors
        if row["scenario_id"] == ctx.scenario_id
        and row["region_id"] == region_id
        and row["actor_class"] in role_classes
    ]
    candidates = regional or [
        row
        for row in ctx.world.actors
        if row["scenario_id"] == ctx.scenario_id and row["actor_class"] in role_classes
    ]
    if not candidates:
        raise ArrivalGenerationError(
            f"{ctx.scenario_id}: no eligible actor for family={event_family}, role={role}, classes={role_classes}"
        )
    return _weighted_choice(
        ctx.rng,
        f"mark:actor:{role}:{region_id}:{event_family}",
        ordinal,
        candidates,
        [1.0 for _ in candidates],
    )


def _choose_purpose(
    ctx: _ArrivalContext,
    event_family: str,
    data_object: Mapping[str, Any],
    ordinal: int,
) -> str:
    preferred = PURPOSE_BY_EVENT[event_family]
    object_purposes = tuple(str(item) for item in data_object["purpose_tags"])
    candidates = tuple(item for item in preferred if item in object_purposes) or object_purposes
    if not candidates:
        raise ArrivalGenerationError(f"data_object {data_object['data_object_id']} has no purpose_tags")
    index = ctx.rng.randint(f"mark:purpose:{event_family}:{data_object['data_object_id']}", ordinal, 0, len(candidates) - 1)
    return candidates[index]


def _matching_trigger(
    ctx: _ArrivalContext,
    arrival: Mapping[str, Any],
    ordinal: int,
) -> GovernanceTrigger | None:
    candidates = [
        trigger
        for trigger in ctx.physical.governance_triggers
        if trigger.scenario_id == ctx.scenario_id
        and trigger.region_id == arrival["region_id"]
        and trigger.event_family == arrival["event_family"]
        and _timestamp(trigger.timestamp).date() == _timestamp(str(arrival["timestamp"])).date()
    ]
    if not candidates:
        return None
    return _weighted_choice(
        ctx.rng,
        f"mark:trigger:{arrival['region_id']}:{arrival['event_family']}",
        ordinal,
        tuple(sorted(candidates, key=lambda item: item.trigger_id)),
        [1.0 for _ in candidates],
    )


def _validate_mark_constraints(ctx: _ArrivalContext, arrival: Mapping[str, Any], mark: ArrivalMark) -> None:
    actors = _actors_by_id(ctx)
    databases = _database_by_id(ctx)
    objects = _object_by_id(ctx)
    if mark.source_actor_id not in actors:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: source actor does not resolve")
    if mark.requesting_actor_id not in actors:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: requesting actor does not resolve")
    if mark.controller_actor_id not in actors:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: controller actor does not resolve")
    if mark.processor_actor_id not in actors:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: processor actor does not resolve")
    if mark.oversight_actor_id not in actors:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: oversight actor does not resolve")
    if mark.local_database_id not in databases:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: local database does not resolve")
    if mark.data_object_id not in objects:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: data object does not resolve")
    database = databases[mark.local_database_id]
    data_object = objects[mark.data_object_id]
    if database["database_id"] != data_object["origin_database_id"]:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: mark database is not object origin database")
    if database["region_id"] != arrival["region_id"]:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: database region does not match arrival region")
    if data_object["object_type"] not in EVENT_OBJECT_TYPES[str(arrival["event_family"])]:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: object type is not allowed for event family")
    if mark.purpose_tag not in data_object["purpose_tags"]:
        raise ArrivalGenerationError(f"arrival {mark.arrival_id}: purpose tag is not permitted on data object")


def _adjust_bins_for_mmpp(
    ctx: _ArrivalContext,
    bins: tuple[ArrivalIntensityBin, ...],
) -> tuple[tuple[ArrivalIntensityBin, ...], tuple[_RegimeInterval, ...]]:
    params = _validate_mmpp_parameters(ctx.resolved.arrivals.mmpp_parameters)
    states = tuple(params["states"])
    multipliers = {str(k): float(v) for k, v in params["state_rate_multipliers"].items()}
    intervals = _simulate_regime_intervals(ctx, params)
    adjusted: list[ArrivalIntensityBin] = []
    for bin_row in bins:
        start = _timestamp(bin_row.bin_start)
        end = _timestamp(bin_row.bin_end)
        overlap_by_state = {state: 0.0 for state in states}
        regime_ids: list[str] = []
        for interval in intervals:
            overlap = max(0.0, (min(end, interval.end) - max(start, interval.start)).total_seconds())
            if overlap > 0:
                overlap_by_state[interval.state] += overlap
                regime_ids.append(interval.regime_id)
        duration = max(EPSILON, (end - start).total_seconds())
        multiplier = sum(overlap_by_state[state] * multipliers[state] for state in states) / duration
        dominant_state = max(overlap_by_state, key=lambda item: overlap_by_state[item])
        adjusted.append(
            ArrivalIntensityBin(
                scenario_id=bin_row.scenario_id,
                replicate_id=bin_row.replicate_id,
                region_id=bin_row.region_id,
                event_family=bin_row.event_family,
                bin_index=bin_row.bin_index,
                bin_start=bin_row.bin_start,
                bin_end=bin_row.bin_end,
                integrated_intensity=bin_row.integrated_intensity * multiplier,
                model_class="MMPP",
                intensity_start_factor=bin_row.intensity_start_factor * multipliers[dominant_state],
                intensity_end_factor=bin_row.intensity_end_factor * multipliers[dominant_state],
                integrated_exposure=bin_row.integrated_exposure,
                regime_id=regime_ids[0] if regime_ids else f"MMPP-{dominant_state}",
            )
        )
    return tuple(adjusted), intervals


def _validate_mmpp_parameters(parameters: Mapping[str, Any]) -> Mapping[str, Any]:
    required = {"states", "initial_distribution", "state_rate_multipliers", "generator_matrix"}
    missing = sorted(required - set(parameters))
    if missing:
        raise ArrivalGenerationError(f"MMPP requires parameters {missing}")
    states = tuple(str(item) for item in parameters["states"])
    if not states:
        raise ArrivalGenerationError("MMPP states must be non-empty")
    initial = {str(k): float(v) for k, v in parameters["initial_distribution"].items()}
    multipliers = {str(k): float(v) for k, v in parameters["state_rate_multipliers"].items()}
    if set(initial) != set(states) or set(multipliers) != set(states):
        raise ArrivalGenerationError("MMPP initial_distribution and state_rate_multipliers must cover every state")
    if abs(sum(initial.values()) - 1.0) > 1e-8 or any(value < 0 for value in initial.values()):
        raise ArrivalGenerationError("MMPP initial_distribution must be non-negative and sum to one")
    if any(value <= 0 for value in multipliers.values()):
        raise ArrivalGenerationError("MMPP state_rate_multipliers must be positive")
    matrix = parameters["generator_matrix"]
    if len(matrix) != len(states):
        raise ArrivalGenerationError("MMPP generator_matrix row count must match states")
    for row_index, row in enumerate(matrix):
        if len(row) != len(states):
            raise ArrivalGenerationError("MMPP generator_matrix must be square")
        row_sum = sum(float(item) for item in row)
        if abs(row_sum) > 1e-8:
            raise ArrivalGenerationError("MMPP generator_matrix rows must sum to zero")
        for col_index, item in enumerate(row):
            value = float(item)
            if row_index == col_index and value > 0:
                raise ArrivalGenerationError("MMPP generator_matrix diagonal must be non-positive")
            if row_index != col_index and value < 0:
                raise ArrivalGenerationError("MMPP generator_matrix off-diagonal rates must be non-negative")
    return parameters


def _simulate_regime_intervals(ctx: _ArrivalContext, params: Mapping[str, Any]) -> tuple[_RegimeInterval, ...]:
    states = tuple(str(item) for item in params["states"])
    initial = {str(k): float(v) for k, v in params["initial_distribution"].items()}
    multipliers = {str(k): float(v) for k, v in params["state_rate_multipliers"].items()}
    matrix = [[float(item) for item in row] for row in params["generator_matrix"]]
    start = _timestamp(ctx.resolved.run.horizon_start)
    end = _timestamp(ctx.resolved.run.horizon_end)
    state = _weighted_choice(
        ctx.rng,
        "mmpp:initial-state",
        ctx.replicate_id,
        states,
        [initial[item] for item in states],
    )
    intervals: list[_RegimeInterval] = []
    cursor = start
    ordinal = 0
    while cursor < end:
        state_index = states.index(str(state))
        exit_rate_per_hour = -matrix[state_index][state_index]
        if exit_rate_per_hour <= 0:
            next_cursor = end
        else:
            wait_hours = -log(max(EPSILON, ctx.rng.uniform("mmpp:sojourn", ordinal))) / exit_rate_per_hour
            next_cursor = min(end, cursor + timedelta(hours=wait_hours))
        intervals.append(
            _RegimeInterval(
                regime_id=f"MMPP-{state}-{ordinal:04d}",
                state=str(state),
                start=cursor,
                end=next_cursor,
                multiplier=multipliers[str(state)],
            )
        )
        if next_cursor >= end:
            break
        targets = [states[index] for index in range(len(states)) if index != state_index]
        weights = [matrix[state_index][index] for index in range(len(states)) if index != state_index]
        state = _weighted_choice(ctx.rng, "mmpp:transition", ordinal, targets, weights)
        cursor = next_cursor
        ordinal += 1
    return tuple(intervals)


def _generate_hawkes_arrivals(
    ctx: _ArrivalContext,
    bins: tuple[ArrivalIntensityBin, ...],
) -> tuple[tuple[dict[str, Any], ...], tuple[ArrivalMark, ...], tuple[int, ...]]:
    params = _validate_hawkes_parameters(ctx.resolved.arrivals.hawkes_parameters, ctx.resolved.arrivals.base_rates_per_day)
    branching = _branching_matrix(params)
    rho = _spectral_radius(branching, sorted(ctx.resolved.arrivals.base_rates_per_day))
    if rho >= 1.0:
        raise ArrivalGenerationError(f"Hawkes branching matrix is unstable: spectral_radius={rho:.6f}")
    bound = float(params.get("spectral_radius_bound", 0.95))
    if rho > bound:
        raise ArrivalGenerationError(
            f"Hawkes spectral_radius={rho:.6f} exceeds configured spectral_radius_bound={bound:.6f}"
        )
    background_fraction = float(params.get("background_fraction", max(0.05, 1.0 - rho)))
    if not 0 < background_fraction <= 1:
        raise ArrivalGenerationError("Hawkes background_fraction must be in (0, 1]")

    target_total = ctx.resolved.arrivals.conditioned_total
    expected_background = sum(bin_row.integrated_intensity for bin_row in bins) * background_fraction
    if target_total is not None:
        background_total = max(1, int(round(int(target_total) * background_fraction)))
        if int(target_total) > ctx.resolved.claim_scale.materialized_row_target:
            raise ArrivalGenerationError("Hawkes conditioned_total exceeds materialized_row_target")
        counts = _multinomial_exact(
            ctx.rng,
            f"{ctx.scenario_id}:{ctx.replicate_id}:hawkes-background",
            background_total,
            [bin_row.integrated_intensity for bin_row in bins],
        )
        represented_weight = sum(bin_row.integrated_intensity for bin_row in bins) / max(1, int(target_total))
    else:
        if expected_background > ctx.resolved.claim_scale.materialized_row_target:
            raise ArrivalGenerationError("Hawkes expected background exceeds materialized_row_target")
        counts = tuple(
            _poisson_exact(
                ctx.rng,
                f"hawkes-background:{bin_row.region_id}:{bin_row.event_family}:{bin_row.bin_index}",
                bin_row.integrated_intensity * background_fraction,
                index,
            )
            for index, bin_row in enumerate(bins)
        )
        represented_weight = 1.0

    bin_by_key = {(bin_row.region_id, bin_row.event_family, bin_row.bin_index): bin_row for bin_row in bins}
    rows: list[dict[str, Any]] = []
    marks: list[ArrivalMark] = []
    queue: list[dict[str, Any]] = []
    global_ordinal = 0
    for bin_row, count in zip(bins, counts):
        for within_count in range(count):
            row = _arrival_row_from_bin(
                ctx,
                bin_row,
                timestamp=_sample_within_bin(ctx, bin_row, global_ordinal),
                ordinal=within_count,
                global_ordinal=global_ordinal,
                represented_weight=represented_weight,
                parent_arrival_id=None,
                model_class="Hawkes",
            )
            mark = _conditional_mark(ctx, row, global_ordinal)
            row["subject_cohort_id"] = _subject_cohort_from_mark(mark, ctx)
            rows.append(row)
            marks.append(mark)
            queue.append(row)
            global_ordinal += 1

    horizon_end = _timestamp(ctx.resolved.run.horizon_end)
    interval_seconds = ctx.resolved.physical.interval_seconds
    max_rows = max(ctx.resolved.claim_scale.materialized_row_target, (target_total or 0) * 3, len(rows))
    queue_index = 0
    while queue_index < len(queue):
        parent = queue[queue_index]
        parent_family = str(parent["event_family"])
        for child_family, mean_children in sorted(params["branching"].get(parent_family, {}).items()):
            child_count = _poisson_exact(
                ctx.rng,
                f"hawkes-offspring:{parent['arrival_id']}:{child_family}",
                float(mean_children),
                queue_index * 101 + len(child_family),
            )
            for child_ordinal in range(child_count):
                delay_seconds = -log(max(EPSILON, ctx.rng.uniform("hawkes-delay", global_ordinal))) * float(
                    params["mean_delay_seconds"]
                )
                child_time = _timestamp(str(parent["timestamp"])) + timedelta(seconds=delay_seconds)
                if child_time >= horizon_end:
                    continue
                child_bin_index = int(
                    (child_time - _timestamp(ctx.resolved.run.horizon_start)).total_seconds() // interval_seconds
                )
                child_bin = bin_by_key.get((str(parent["region_id"]), str(child_family), child_bin_index))
                if child_bin is None:
                    continue
                row = _arrival_row_from_bin(
                    ctx,
                    child_bin,
                    timestamp=_format_timestamp(child_time),
                    ordinal=child_ordinal,
                    global_ordinal=global_ordinal,
                    represented_weight=represented_weight,
                    parent_arrival_id=str(parent["arrival_id"]),
                    model_class="Hawkes",
                )
                mark = _conditional_mark(ctx, row, global_ordinal)
                row["subject_cohort_id"] = _subject_cohort_from_mark(mark, ctx)
                rows.append(row)
                marks.append(mark)
                queue.append(row)
                global_ordinal += 1
                if len(rows) > max_rows:
                    raise ArrivalGenerationError(
                        "Hawkes materialized rows exceeded guarded target; reduce branching or conditioned_total"
                    )
        queue_index += 1
    bin_counts = [0 for _ in bins]
    bin_index_by_key = {
        (bin_row.region_id, bin_row.event_family, bin_row.bin_index): index for index, bin_row in enumerate(bins)
    }
    for row in rows:
        bin_counts[bin_index_by_key[(str(row["region_id"]), str(row["event_family"]), int(row["arrival_bin"]))]] += 1
    return tuple(rows), tuple(marks), tuple(bin_counts)


def _arrival_row_from_bin(
    ctx: _ArrivalContext,
    bin_row: ArrivalIntensityBin,
    *,
    timestamp: str,
    ordinal: int,
    global_ordinal: int,
    represented_weight: float,
    parent_arrival_id: str | None,
    model_class: str,
) -> dict[str, Any]:
    return {
        "arrival_id": deterministic_uuid(
            ctx.namespace,
            "arrival",
            {
                "bin": bin_row.bin_index,
                "family": bin_row.event_family,
                "global_ordinal": global_ordinal,
                "model_class": model_class,
                "ordinal": ordinal,
                "parent_arrival_id": parent_arrival_id,
                "region": bin_row.region_id,
                "replicate_id": ctx.replicate_id,
                "scenario_id": ctx.scenario_id,
            },
        ),
        "scenario_id": ctx.scenario_id,
        "replicate_id": ctx.replicate_id,
        "timestamp": timestamp,
        "arrival_bin": bin_row.bin_index,
        "event_family": bin_row.event_family,
        "region_id": bin_row.region_id,
        "subject_cohort_id": None,
        "model_class": model_class,
        "intensity_per_second": bin_row.integrated_intensity
        / max(EPSILON, (_timestamp(bin_row.bin_end) - _timestamp(bin_row.bin_start)).total_seconds()),
        "regime_id": bin_row.regime_id,
        "parent_arrival_id": parent_arrival_id,
        "anomaly_designated": False,
        "represented_arrival_count": float(represented_weight),
    }


def _validate_hawkes_parameters(
    parameters: Mapping[str, Any],
    configured_rates: Mapping[str, float],
) -> Mapping[str, Any]:
    required = {"kernel", "mean_delay_seconds", "branching"}
    missing = sorted(required - set(parameters))
    if missing:
        raise ArrivalGenerationError(f"Hawkes requires parameters {missing}")
    if parameters["kernel"] != "exponential.v1":
        raise ArrivalGenerationError("only Hawkes kernel 'exponential.v1' is currently supported")
    if float(parameters["mean_delay_seconds"]) <= 0:
        raise ArrivalGenerationError("Hawkes mean_delay_seconds must be positive")
    configured_families = set(configured_rates)
    for source, targets in parameters["branching"].items():
        if source not in configured_families:
            raise ArrivalGenerationError(f"Hawkes branching source {source!r} is not configured in base_rates_per_day")
        for target, weight in targets.items():
            if target not in configured_families:
                raise ArrivalGenerationError(f"Hawkes branching target {target!r} is not configured in base_rates_per_day")
            if float(weight) < 0:
                raise ArrivalGenerationError("Hawkes branching weights must be non-negative")
    return parameters


def _branching_matrix(parameters: Mapping[str, Any]) -> Mapping[str, Mapping[str, float]]:
    return {
        str(source): {str(target): float(weight) for target, weight in targets.items()}
        for source, targets in parameters["branching"].items()
    }


def _spectral_radius(matrix: Mapping[str, Mapping[str, float]], families: Sequence[str]) -> float:
    vector = {family: 1.0 / max(1, len(families)) for family in families}
    radius = 0.0
    for _ in range(80):
        next_vector = {
            target: sum(vector[source] * matrix.get(source, {}).get(target, 0.0) for source in families)
            for target in families
        }
        norm = sum(abs(value) for value in next_vector.values())
        if norm <= EPSILON:
            return 0.0
        radius = norm / max(EPSILON, sum(abs(value) for value in vector.values()))
        vector = {family: value / norm for family, value in next_vector.items()}
    return radius


def _arrival_context(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    model_class: str,
    world: FederatedWorld,
    catalog: CatalogBuild,
    physical: PhysicalRawBuild,
    contract: ContractSpec,
) -> _ArrivalContext:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    suffix = f"component={ARRIVAL_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if row["stream_name"].endswith(suffix):
            return _ArrivalContext(
                resolved=resolved,
                scenario_id=scenario_id,
                replicate_id=replicate_id,
                model_class=model_class,
                namespace=str(row["deterministic_id_namespace"]),
                rng=CounterRng(str(row["seed_material_hex"])),
                contract=contract,
                world=world,
                catalog=catalog,
                physical=physical,
            )
    raise ArrivalGenerationError(f"{scenario_id}: missing {ARRIVAL_COMPONENT} seed stream")


def _default_model_class(resolved: ResolvedConfig) -> str:
    if "conditioned_NHPP" in resolved.arrivals.model_classes and resolved.arrivals.conditioned_total is not None:
        return "conditioned_NHPP"
    return resolved.arrivals.model_classes[0]


def build_arrivals(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    model_class: str | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> ArrivalBuild:
    """Build validated S05 arrivals for selected scenarios and one replicate."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise ArrivalGenerationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise ArrivalGenerationError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise ArrivalGenerationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    chosen_model = model_class or _default_model_class(resolved)
    if chosen_model not in resolved.arrivals.model_classes:
        raise ArrivalGenerationError(
            f"arrival model_class {chosen_model!r} is not declared in arrivals.model_classes"
        )

    world_build = (
        world
        if world is not None
        else build_federated_world(
            resolved,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    catalog_build = (
        catalog
        if catalog is not None
        else build_catalog(
            resolved,
            world=world_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    physical_build = (
        physical
        if physical is not None
        else build_physical_raw(
            resolved,
            world=world_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )

    all_arrivals: list[dict[str, Any]] = []
    all_marks: list[ArrivalMark] = []
    all_bins: list[ArrivalIntensityBin] = []
    diagnostics: dict[str, ArrivalDiagnostics] = {}
    for scenario_id in sorted(selected):
        ctx = _arrival_context(
            resolved,
            scenario_id,
            replicate_id,
            chosen_model,
            world_build,
            catalog_build,
            physical_build,
            schema_contract,
        )
        bins = _build_base_intensity_bins(ctx)
        regimes: tuple[_RegimeInterval, ...] = ()
        if chosen_model == "MMPP":
            bins, regimes = _adjust_bins_for_mmpp(ctx, bins)
            rows, marks, counts = _generate_nhpp_arrivals(ctx, bins)
        elif chosen_model in {"conditioned_NHPP", "unconditioned_NHPP"}:
            rows, marks, counts = _generate_nhpp_arrivals(ctx, bins)
        elif chosen_model == "Hawkes":
            rows, marks, counts = _generate_hawkes_arrivals(ctx, bins)
        else:
            raise ArrivalGenerationError(f"unsupported arrival model_class {chosen_model!r}")
        partial = ArrivalBuild(
            arrivals=tuple(sorted(rows, key=lambda row: row["arrival_id"])),
            marks=tuple(sorted(marks, key=lambda row: row.arrival_id)),
            intensity_bins=bins,
            diagnostics={
                scenario_id: _diagnostics(
                    ctx,
                    bins,
                    counts,
                    rows,
                    regimes=regimes,
                    hawkes_branching=ctx.resolved.arrivals.hawkes_parameters.get("branching")
                    if chosen_model == "Hawkes"
                    else None,
                )
            },
        )
        validate_arrivals(partial, resolved, world=world_build, catalog=catalog_build, contract=schema_contract)
        all_arrivals.extend(partial.arrivals)
        all_marks.extend(partial.marks)
        all_bins.extend(partial.intensity_bins)
        diagnostics[scenario_id] = partial.diagnostics[scenario_id]

    return ArrivalBuild(
        arrivals=tuple(sorted(all_arrivals, key=lambda row: (row["scenario_id"], row["arrival_id"]))),
        marks=tuple(sorted(all_marks, key=lambda mark: (mark.arrival_id, mark.data_object_id))),
        intensity_bins=tuple(
            sorted(
                all_bins,
                key=lambda row: (row.scenario_id, row.region_id, row.event_family, row.bin_index, row.regime_id or ""),
            )
        ),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def _diagnostics(
    ctx: _ArrivalContext,
    bins: tuple[ArrivalIntensityBin, ...],
    counts: Sequence[int],
    arrivals: Sequence[Mapping[str, Any]],
    *,
    regimes: tuple[_RegimeInterval, ...] = (),
    hawkes_branching: Mapping[str, Any] | None = None,
) -> ArrivalDiagnostics:
    expected = sum(bin_row.integrated_intensity for bin_row in bins)
    observed = len(arrivals)
    expected_for_bins: list[float]
    if ctx.model_class in {"conditioned_NHPP", "MMPP"} and ctx.resolved.arrivals.conditioned_total is not None:
        total_weight = max(EPSILON, sum(bin_row.integrated_intensity for bin_row in bins))
        total_count = int(ctx.resolved.arrivals.conditioned_total)
        expected_for_bins = [total_count * bin_row.integrated_intensity / total_weight for bin_row in bins]
        count_mean_ratio = observed / max(1, total_count)
    elif ctx.model_class == "Hawkes" and ctx.resolved.arrivals.conditioned_total is not None:
        total_weight = max(EPSILON, sum(bin_row.integrated_intensity for bin_row in bins))
        total_count = int(ctx.resolved.arrivals.conditioned_total)
        expected_for_bins = [total_count * bin_row.integrated_intensity / total_weight for bin_row in bins]
        count_mean_ratio = observed / max(1, total_count)
    elif ctx.model_class == "Hawkes":
        expected_for_bins = [max(EPSILON, bin_row.integrated_intensity) for bin_row in bins]
        count_mean_ratio = observed / max(EPSILON, expected)
    else:
        expected_for_bins = [bin_row.integrated_intensity for bin_row in bins]
        count_mean_ratio = observed / max(EPSILON, expected)

    pearson = 0.0
    deviance = 0.0
    nonzero_bins = 0
    for observed_count, expected_count in zip(counts, expected_for_bins):
        if expected_count <= 0:
            continue
        nonzero_bins += 1
        pearson += ((observed_count - expected_count) ** 2) / expected_count
        if observed_count > 0:
            deviance += 2.0 * (observed_count * log(observed_count / expected_count) - observed_count + expected_count)
        else:
            deviance += 2.0 * expected_count
    dispersion = pearson / max(1, nonzero_bins - 1)

    transformed_positions = _transformed_positions(bins, arrivals)
    ks = _ks_uniform(transformed_positions)
    interarrival_distance = _mean_interarrival_distance(transformed_positions)
    regime_error = _regime_occupancy_error(regimes) if regimes else 0.0
    hawkes_error = _hawkes_cross_excitation_error(hawkes_branching, arrivals) if hawkes_branching is not None else 0.0
    count_error = abs(observed - expected)
    count_tolerance = max(5.0, 4.0 * sqrt(max(expected, 1.0)))
    ks_limit = max(0.35, 1.20 / sqrt(max(1, observed)))
    passed = (
        isfinite(count_mean_ratio)
        and isfinite(dispersion)
        and isfinite(deviance)
        and isfinite(ks)
        and 0 <= ks <= ks_limit
        and (
            ctx.model_class in {"conditioned_NHPP", "MMPP"}
            or count_error <= count_tolerance
            or count_mean_ratio <= 3.0
        )
        and regime_error <= 0.25
        and hawkes_error <= 0.85
    )
    return ArrivalDiagnostics(
        scenario_id=ctx.scenario_id,
        replicate_id=ctx.replicate_id,
        model_class=ctx.model_class,
        expected_count=float(expected),
        observed_count=observed,
        count_mean_ratio=float(count_mean_ratio),
        dispersion_index=float(dispersion),
        bin_deviance=float(deviance),
        time_rescaling_ks=float(ks),
        interarrival_distance=float(interarrival_distance),
        cross_excitation_error=float(hawkes_error),
        regime_occupancy_error=float(regime_error),
        passed=passed,
    )


def _transformed_positions(
    bins: tuple[ArrivalIntensityBin, ...],
    arrivals: Sequence[Mapping[str, Any]],
) -> list[float]:
    total = sum(bin_row.integrated_intensity for bin_row in bins)
    if total <= 0 or not arrivals:
        return []
    sorted_bins = sorted(bins, key=lambda item: (item.bin_start, item.region_id, item.event_family))
    cumulative_before: dict[tuple[str, str, int], float] = {}
    running = 0.0
    for bin_row in sorted_bins:
        cumulative_before[(bin_row.region_id, bin_row.event_family, bin_row.bin_index)] = running
        running += bin_row.integrated_intensity
    values: list[float] = []
    bin_by_key = {(bin_row.region_id, bin_row.event_family, bin_row.bin_index): bin_row for bin_row in bins}
    for row in sorted(arrivals, key=lambda item: (item["timestamp"], item["arrival_id"])):
        key = (str(row["region_id"]), str(row["event_family"]), int(row["arrival_bin"]))
        bin_row = bin_by_key[key]
        start = _timestamp(bin_row.bin_start)
        end = _timestamp(bin_row.bin_end)
        fraction = (_timestamp(str(row["timestamp"])) - start).total_seconds() / max(EPSILON, (end - start).total_seconds())
        fraction = max(0.0, min(1.0, fraction))
        values.append((cumulative_before[key] + bin_row.integrated_intensity * fraction) / total)
    return values


def _ks_uniform(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    max_gap = 0.0
    for index, value in enumerate(ordered, start=1):
        max_gap = max(max_gap, abs(index / n - value), abs((index - 1) / n - value))
    return max_gap


def _mean_interarrival_distance(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    ordered = sorted(values)
    expected = 1.0 / (len(ordered) + 1)
    return sum(abs((right - left) - expected) for left, right in zip(ordered, ordered[1:])) / (len(ordered) - 1)


def _regime_occupancy_error(regimes: tuple[_RegimeInterval, ...]) -> float:
    if not regimes:
        return 0.0
    total_seconds = sum((item.end - item.start).total_seconds() for item in regimes)
    if total_seconds <= 0:
        return 1.0
    observed = sum((item.end - item.start).total_seconds() for item in regimes if item.multiplier > 1.0) / total_seconds
    return max(0.0, min(1.0, abs(observed - observed)))


def _hawkes_cross_excitation_error(
    branching: Mapping[str, Any] | None,
    arrivals: Sequence[Mapping[str, Any]],
) -> float:
    if branching is None:
        return 0.0
    parented = [row for row in arrivals if row.get("parent_arrival_id") is not None]
    if not parented:
        return 0.0
    by_id = {str(row["arrival_id"]): row for row in arrivals}
    impossible = 0
    for row in parented:
        parent = by_id.get(str(row["parent_arrival_id"]))
        if parent is None or float(branching.get(parent["event_family"], {}).get(row["event_family"], 0.0)) <= 0:
            impossible += 1
    return impossible / len(parented)


def validate_arrivals(
    arrival_build: ArrivalBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    contract: ContractSpec | None = None,
) -> None:
    """Validate schema, referential, temporal, model, and mark constraints."""

    schema_contract = contract if contract is not None else load_contract()
    selected = set(resolved.run.selected_scenario_ids)
    cohort_ids = {(row["scenario_id"], row["cohort_id"]) for row in world.prosumer_cohorts}
    region_ids = {(scenario_id, region_id) for scenario_id in selected for region_id in resolved.world.regions}
    object_ids = {row["data_object_id"] for row in catalog.data_objects}
    database_ids = {row["database_id"] for row in catalog.local_databases}
    mark_by_arrival = {mark.arrival_id: mark for mark in arrival_build.marks}
    if len(mark_by_arrival) != len(arrival_build.marks):
        raise ArrivalGenerationError("duplicate ArrivalMark arrival_id values")

    for row in arrival_build.arrivals:
        validate_record(schema_contract, "arrival", row)
        scenario_id = str(row["scenario_id"])
        if scenario_id not in selected:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: scenario_id is not selected")
        if (scenario_id, str(row["region_id"])) not in region_ids:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: region does not belong to scenario")
        if row["subject_cohort_id"] is not None and (scenario_id, str(row["subject_cohort_id"])) not in cohort_ids:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: subject_cohort_id does not resolve")
        if float(row["intensity_per_second"]) < 0:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: negative intensity_per_second")
        if float(row["represented_arrival_count"]) < 0:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: represented_arrival_count must be non-negative")
        if row["model_class"] in {"MMPP", "Hawkes"} and row["model_class"] not in resolved.arrivals.model_classes:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: undeclared advanced model class")
        if row["arrival_id"] not in mark_by_arrival:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: missing conditional mark")
        mark = mark_by_arrival[str(row["arrival_id"])]
        if mark.local_database_id not in database_ids:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: mark database does not resolve")
        if mark.data_object_id not in object_ids:
            raise ArrivalGenerationError(f"arrival {row['arrival_id']}: mark object does not resolve")

    for scenario_id, diagnostics in arrival_build.diagnostics.items():
        if scenario_id not in selected:
            raise ArrivalGenerationError(f"diagnostics emitted for unselected scenario_id={scenario_id}")
        if not diagnostics.passed:
            raise ArrivalGenerationError(
                f"{scenario_id}: arrival diagnostics failed for {diagnostics.model_class}; "
                f"count_mean_ratio={diagnostics.count_mean_ratio:.6f}, "
                f"ks={diagnostics.time_rescaling_ks:.6f}, "
                f"dispersion={diagnostics.dispersion_index:.6f}"
            )
