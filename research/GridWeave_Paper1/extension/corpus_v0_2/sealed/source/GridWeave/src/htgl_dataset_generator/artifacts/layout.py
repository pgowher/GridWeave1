"""Contract-owned S15 table layout and deterministic partition rules."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import quote


TABLE_ROOTS: Mapping[str, str] = {
    "run_scenario": "config/run_scenario",
    "seed_stream": "provenance/seed_stream",
    "actor": "canonical/world/actor",
    "actor_relationship": "canonical/world/actor_relationship",
    "prosumer_cohort": "canonical/world/prosumer_cohort",
    "network_area": "canonical/world/network_area",
    "local_database": "canonical/catalog/local_database",
    "data_object": "canonical/catalog/data_object",
    "data_object_replica": "canonical/catalog/data_object_replica",
    "raw_meter_reading": "raw/meter",
    "raw_der_telemetry": "raw/der",
    "raw_network_state": "raw/network",
    "raw_context_event": "raw/context",
    "arrival": "canonical/arrivals",
    "governance_event": "canonical/events",
    "event_edge": "canonical/edges",
    "workflow_instance": "canonical/workflows",
    "policy_rule": "canonical/policy/rules",
    "policy_decision_truth": "truth/policy",
    "anomaly_instance": "truth/anomalies",
    "evidence_obligation": "truth/obligations",
    "evidence_receipt": "truth/evidence",
    "observer_event": "observers/evaluator/observer_event",
    "sampling_design": "samples/design",
    "sample_membership": "samples/evaluator/membership",
    "validation_issue": "validation/issues",
    "run_metric": "metrics/run_metric",
}


FACT_DATE_FIELDS: Mapping[str, str] = {
    "raw_meter_reading": "interval_start",
    "raw_der_telemetry": "timestamp",
    "raw_network_state": "timestamp",
    "raw_context_event": "timestamp",
    "arrival": "timestamp",
    "governance_event": "timestamp",
    "observer_event": "visible_timestamp",
}


REGION_FIELDS: Mapping[str, str] = {
    "raw_meter_reading": "region_id",
    "raw_der_telemetry": "region_id",
    "raw_network_state": "region_id",
    "raw_context_event": "region_id",
    "arrival": "region_id",
}


def safe_partition_value(value: Any) -> str:
    """Encode one partition value without allowing path traversal or separators."""

    token = quote(str(value), safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    if not token or token in {".", ".."}:
        raise ValueError(f"unsafe empty or traversal partition value {value!r}")
    return token


def table_partition_groups(
    table_name: str,
    records: Sequence[Mapping[str, Any]],
    *,
    scenario_id: str,
    replicate_id: int,
    configured_partition_keys: Sequence[str],
    fact_partition_minimum_rows: int,
    region_partition_minimum_rows: int,
    minimum_rows_per_region_partition: int,
) -> tuple[tuple[tuple[tuple[str, str], ...], tuple[Mapping[str, Any], ...]], ...]:
    """Return deterministic non-tiny partition groups for one replicate table."""

    if table_name not in TABLE_ROOTS:
        raise KeyError(f"S15 has no release layout owner for table {table_name!r}")
    base = (
        ("scenario_id", safe_partition_value(scenario_id)),
        ("replicate_id", safe_partition_value(replicate_id)),
    )
    date_field = FACT_DATE_FIELDS.get(table_name)
    use_date = (
        date_field is not None
        and "date" in configured_partition_keys
        and len(records) >= fact_partition_minimum_rows
    )
    region_field = REGION_FIELDS.get(table_name)
    region_values = {
        str(row[region_field])
        for row in records
        if region_field is not None and row.get(region_field) is not None
    }
    use_region = (
        region_field is not None
        and "region_id" in configured_partition_keys
        and len(records) >= region_partition_minimum_rows
        and len(region_values) > 1
        and len(records) / len(region_values) >= minimum_rows_per_region_partition
    )
    groups: dict[tuple[tuple[str, str], ...], list[Mapping[str, Any]]] = {}
    for row in records:
        keys = list(base)
        if use_date:
            raw_timestamp = str(row[date_field])
            if len(raw_timestamp) < 10:
                raise ValueError(
                    f"{table_name}.{date_field} cannot provide an ISO date partition: {raw_timestamp!r}"
                )
            keys.append(("date", safe_partition_value(raw_timestamp[:10])))
        if use_region:
            keys.append(("region_id", safe_partition_value(row[region_field])))
        groups.setdefault(tuple(keys), []).append(row)
    if not groups:
        groups[base] = []
    return tuple(
        (key, tuple(value))
        for key, value in sorted(groups.items(), key=lambda item: item[0])
    )


def partition_relative_path(
    table_name: str,
    partition: Sequence[tuple[str, str]],
    *,
    part_index: int = 0,
) -> str:
    root = PurePosixPath(TABLE_ROOTS[table_name])
    for key, value in partition:
        root /= f"{key}={value}"
    return str(root / f"part-{part_index:05d}.parquet")

