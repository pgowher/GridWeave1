"""S03 catalog, data-object, replica, and custody builder."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import ceil
from typing import Any, Iterable, Mapping
import hashlib
import json

from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, deterministic_uuid, seed_stream_records_for_plan
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


CATALOG_COMPONENT = "S03.catalog"
REQUIRED_OBJECT_TYPES: tuple[str, ...] = (
    "meter_interval",
    "profile",
    "bill",
    "consent",
    "model_feature",
    "market_bid",
    "operational_command",
    "audit_record",
    "evidence_record",
)
REQUIRED_REPLICA_ROLES: tuple[str, ...] = (
    "primary",
    "secondary",
    "cache",
    "backup",
    "export",
    "derived",
)

DATABASE_KIND_OBJECT_TYPES: Mapping[str, tuple[str, ...]] = {
    "meter_data": ("meter_interval", "profile", "model_feature"),
    "billing": ("bill", "profile", "meter_interval"),
    "derms": ("operational_command", "meter_interval"),
    "crm": ("consent", "profile"),
    "market": ("market_bid", "profile"),
    "audit": ("audit_record", "evidence_record"),
    "archive": REQUIRED_OBJECT_TYPES,
    "consent_registry": ("consent",),
    "model_feature_store": ("model_feature", "profile", "meter_interval"),
}

OBJECT_PRIMARY_DATABASE_KIND: Mapping[str, str] = {
    "meter_interval": "meter_data",
    "profile": "meter_data",
    "bill": "billing",
    "consent": "consent_registry",
    "model_feature": "model_feature_store",
    "market_bid": "market",
    "operational_command": "derms",
    "audit_record": "audit",
    "evidence_record": "audit",
}

DATABASE_STORAGE_CLASS: Mapping[str, str] = {
    "meter_data": "primary",
    "billing": "primary",
    "derms": "primary",
    "crm": "primary",
    "market": "primary",
    "audit": "immutable_log",
    "archive": "archive",
    "consent_registry": "primary",
    "model_feature_store": "cache",
}

OBJECT_SENSITIVITY: Mapping[str, str] = {
    "meter_interval": "high",
    "profile": "moderate",
    "bill": "high",
    "consent": "restricted",
    "model_feature": "moderate",
    "market_bid": "moderate",
    "operational_command": "restricted",
    "audit_record": "restricted",
    "evidence_record": "restricted",
}

OBJECT_PURPOSES: Mapping[str, tuple[str, ...]] = {
    "meter_interval": ("metering", "billing", "grid_operations"),
    "profile": ("analytics", "forecasting"),
    "bill": ("billing", "customer_accounting"),
    "consent": ("consent_management", "rights_management"),
    "model_feature": ("model_training", "forecasting"),
    "market_bid": ("market_operations",),
    "operational_command": ("grid_operations", "der_dispatch"),
    "audit_record": ("audit", "oversight"),
    "evidence_record": ("evidence", "oversight"),
}

PHYSICAL_SOURCE_OBJECT_TYPES = frozenset(
    {"meter_interval", "profile", "model_feature", "operational_command"}
)

DERIVATION_SOURCES: Mapping[str, tuple[str, ...]] = {
    "profile": ("meter_interval",),
    "bill": ("meter_interval", "consent"),
    "model_feature": ("meter_interval", "profile"),
    "market_bid": ("profile",),
    "operational_command": ("market_bid", "profile"),
    "audit_record": ("meter_interval", "consent", "operational_command"),
    "evidence_record": ("audit_record",),
}


class CatalogBuildError(ValueError):
    """Raised when S03 catalog/custody rows cannot satisfy the contract."""


@dataclass(frozen=True)
class CustodyEdge:
    edge_id: str
    scenario_id: str
    edge_type: str
    source_id: str
    target_id: str
    source_table: str
    target_table: str
    reason_code: str


@dataclass(frozen=True)
class CatalogDiagnostics:
    scenario_id: str
    local_database_count: int
    data_object_count: int
    replica_count: int
    custody_edge_count: int
    database_counts_by_kind: Mapping[str, int]
    object_counts_by_type: Mapping[str, int]
    replica_counts_by_role: Mapping[str, int]


@dataclass(frozen=True)
class CatalogBuild:
    local_databases: tuple[dict[str, Any], ...]
    data_objects: tuple[dict[str, Any], ...]
    data_object_replicas: tuple[dict[str, Any], ...]
    custody_edges: tuple[CustodyEdge, ...]
    diagnostics: Mapping[str, CatalogDiagnostics]

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "local_database": self.local_databases,
            "data_object": self.data_objects,
            "data_object_replica": self.data_object_replicas,
        }


@dataclass(frozen=True)
class _CatalogContext:
    resolved: ResolvedConfig
    scenario_id: str
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    world: FederatedWorld


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stable_score(namespace: str, label: str, payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json({"label": label, "namespace": namespace, "payload": payload}).encode("utf-8")
    ).hexdigest()


def _normalize_token(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_").upper()


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _catalog_context(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    world: FederatedWorld,
    contract: ContractSpec,
) -> _CatalogContext:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    suffix = f"component={CATALOG_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if row["stream_name"].endswith(suffix):
            return _CatalogContext(
                resolved=resolved,
                scenario_id=scenario_id,
                namespace=str(row["deterministic_id_namespace"]),
                rng=CounterRng(str(row["seed_material_hex"])),
                contract=contract,
                world=world,
            )
    raise CatalogBuildError(f"{scenario_id}: missing {CATALOG_COMPONENT} seed stream")


def _actor_for_region(
    actors: Iterable[Mapping[str, Any]],
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
        raise CatalogBuildError(f"no actor found for classes {actor_classes} near region {region_id}")
    return sorted(candidates, key=lambda row: row["actor_id"])[0]


def _database_kind_from_profile(profile_id: str) -> str | None:
    token = _normalize_token(profile_id)
    mapping = (
        ("METER", "meter_data"),
        ("BILL", "billing"),
        ("DER", "derms"),
        ("CRM", "crm"),
        ("MARKET", "market"),
        ("AUDIT", "audit"),
        ("ARCHIVE", "archive"),
        ("CONSENT", "consent_registry"),
        ("FEATURE", "model_feature_store"),
    )
    for needle, database_kind in mapping:
        if needle in token:
            return database_kind
    return None


def _configured_database_kinds(resolved: ResolvedConfig) -> tuple[str, ...]:
    kinds = {
        kind
        for profile_id in resolved.catalog.database_profiles
        for kind in (_database_kind_from_profile(profile_id),)
        if kind is not None
    }
    kinds.update(OBJECT_PRIMARY_DATABASE_KIND[object_type] for object_type in REQUIRED_OBJECT_TYPES)
    kinds.add("archive")
    return tuple(sorted(kinds))


def _region_counts(world: FederatedWorld, scenario_id: str) -> Mapping[str, tuple[int, int]]:
    counts: dict[str, tuple[int, int]] = {}
    for cohort in world.prosumer_cohorts:
        if cohort["scenario_id"] != scenario_id:
            continue
        region_id = str(cohort["region_id"])
        consumers, prosumers = counts.get(region_id, (0, 0))
        counts[region_id] = (
            consumers + int(cohort["represented_consumer_count"]),
            prosumers + int(cohort["represented_prosumer_count"]),
        )
    return dict(sorted(counts.items()))


def _represented_record_count(database_kind: str, consumers: int, prosumers: int, intervals_per_horizon: int) -> int:
    total = consumers + prosumers
    if database_kind == "meter_data":
        return total * intervals_per_horizon
    if database_kind == "billing":
        return total
    if database_kind == "derms":
        return max(1, prosumers * intervals_per_horizon)
    if database_kind == "market":
        return max(1, prosumers)
    if database_kind == "audit":
        return max(1, ceil(total / 10))
    if database_kind == "archive":
        return max(1, total * 2)
    if database_kind == "consent_registry":
        return total
    if database_kind == "model_feature_store":
        return max(1, total * 10)
    if database_kind == "crm":
        return total
    raise CatalogBuildError(f"unsupported database_kind {database_kind!r}")


def _operator_classes(database_kind: str) -> tuple[str, ...]:
    return {
        "meter_data": ("dso", "processor"),
        "billing": ("supplier", "processor"),
        "derms": ("dso", "aggregator", "processor"),
        "crm": ("supplier", "processor"),
        "market": ("aggregator", "supplier", "tso"),
        "audit": ("auditor", "regulator"),
        "archive": ("processor", "vendor", "dso"),
        "consent_registry": ("dso", "supplier", "processor"),
        "model_feature_store": ("processor", "vendor", "aggregator"),
    }[database_kind]


def _build_local_databases(ctx: _CatalogContext) -> tuple[dict[str, Any], ...]:
    actors = tuple(actor for actor in ctx.world.actors if actor["scenario_id"] == ctx.scenario_id)
    region_counts = _region_counts(ctx.world, ctx.scenario_id)
    if not region_counts:
        raise CatalogBuildError(f"{ctx.scenario_id}: no world cohorts available for catalog")
    intervals = max(
        1,
        int(
            (_timestamp(ctx.resolved.run.horizon_end) - _timestamp(ctx.resolved.run.horizon_start)).total_seconds()
            // ctx.resolved.physical.interval_seconds
        ),
    )
    rows: list[dict[str, Any]] = []
    for region_id, (consumers, prosumers) in region_counts.items():
        controller = _actor_for_region(actors, actor_classes=("dso", "tso"), region_id=region_id)
        for database_kind in _configured_database_kinds(ctx.resolved):
            operator = _actor_for_region(
                actors,
                actor_classes=_operator_classes(database_kind),
                region_id=region_id,
            )
            represented_records = _represented_record_count(database_kind, consumers, prosumers, intervals)
            database_id = deterministic_uuid(
                ctx.namespace,
                "local_database",
                {
                    "scenario_id": ctx.scenario_id,
                    "region_id": region_id,
                    "database_kind": database_kind,
                },
            )
            row = {
                "database_id": database_id,
                "scenario_id": ctx.scenario_id,
                "controller_actor_id": controller["actor_id"],
                "operator_actor_id": operator["actor_id"],
                "region_id": region_id,
                "database_kind": database_kind,
                "storage_class": DATABASE_STORAGE_CLASS[database_kind],
                "supported_object_types": list(DATABASE_KIND_OBJECT_TYPES[database_kind]),
                "represented_record_count": represented_records,
                "retention_profile_id": _retention_profile(ctx, database_kind),
                "encryption_profile_id": _encryption_profile(ctx, database_kind),
                "capacity_records": ceil(represented_records * 1.25),
            }
            validate_record(ctx.contract, "local_database", row)
            rows.append(row)
    return tuple(sorted(rows, key=lambda row: (row["scenario_id"], row["region_id"], row["database_kind"])))


def _retention_profile(ctx: _CatalogContext, discriminator: str) -> str:
    profiles = tuple(ctx.resolved.catalog.retention_profiles)
    if not profiles:
        raise CatalogBuildError(f"{ctx.scenario_id}: at least one retention profile is required")
    index = ctx.rng.randint(f"retention:{discriminator}", 0, 0, len(profiles) - 1)
    return profiles[index]


def _encryption_profile(ctx: _CatalogContext, discriminator: str) -> str | None:
    profiles = tuple(ctx.resolved.catalog.security_profiles)
    if not profiles:
        return None
    index = ctx.rng.randint(f"security:{discriminator}", 0, 0, len(profiles) - 1)
    return profiles[index]


def _db_by_region_kind(databases: Iterable[Mapping[str, Any]]) -> Mapping[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(database["region_id"]), str(database["database_kind"])): database
        for database in databases
    }


def _first_cohort_for_region(world: FederatedWorld, scenario_id: str, region_id: str) -> str | None:
    cohorts = [
        cohort
        for cohort in world.prosumer_cohorts
        if cohort["scenario_id"] == scenario_id and cohort["region_id"] == region_id
    ]
    if not cohorts:
        return None
    return str(sorted(cohorts, key=lambda row: row["cohort_id"])[0]["cohort_id"])


def _source_physical_record_ids(ctx: _CatalogContext, region_id: str, object_type: str) -> list[str]:
    if object_type not in PHYSICAL_SOURCE_OBJECT_TYPES:
        return []
    source_id = deterministic_uuid(
        ctx.namespace,
        "source_physical_record_ref",
        {
            "scenario_id": ctx.scenario_id,
            "region_id": region_id,
            "object_type": object_type,
            "backend": ctx.resolved.physical.backend,
        },
    )
    return [source_id]


def _build_data_objects(
    ctx: _CatalogContext,
    databases: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    db_index = _db_by_region_kind(databases)
    rows: list[dict[str, Any]] = []
    for region_id in sorted(ctx.resolved.world.regions):
        for object_type in REQUIRED_OBJECT_TYPES:
            database_kind = OBJECT_PRIMARY_DATABASE_KIND[object_type]
            origin = db_index.get((region_id, database_kind))
            if origin is None:
                raise CatalogBuildError(
                    f"{ctx.scenario_id}: missing {database_kind} database for {object_type} in {region_id}"
                )
            object_id = deterministic_uuid(
                ctx.namespace,
                "data_object",
                {
                    "scenario_id": ctx.scenario_id,
                    "region_id": region_id,
                    "object_type": object_type,
                },
            )
            subject_cohort_id = (
                _first_cohort_for_region(ctx.world, ctx.scenario_id, region_id)
                if object_type in {"meter_interval", "profile", "bill", "consent", "model_feature"}
                else None
            )
            row = {
                "data_object_id": object_id,
                "scenario_id": ctx.scenario_id,
                "origin_database_id": origin["database_id"],
                "object_type": object_type,
                "subject_cohort_id": subject_cohort_id,
                "sensitivity": OBJECT_SENSITIVITY[object_type],
                "schema_id": f"htgl.object.v1.{object_type}",
                "created_at": ctx.resolved.run.horizon_start,
                "valid_from": ctx.resolved.run.horizon_start,
                "valid_to": ctx.resolved.run.horizon_end,
                "source_physical_record_ids": _source_physical_record_ids(ctx, region_id, object_type),
                "purpose_tags": list(OBJECT_PURPOSES[object_type]),
            }
            validate_record(ctx.contract, "data_object", row)
            rows.append(row)
    return tuple(sorted(rows, key=lambda row: (row["scenario_id"], row["object_type"], row["data_object_id"])))


def _database_for_role(
    data_object: Mapping[str, Any],
    databases: tuple[dict[str, Any], ...],
    role: str,
) -> Mapping[str, Any]:
    origin = next(database for database in databases if database["database_id"] == data_object["origin_database_id"])
    region_id = str(origin["region_id"])
    object_type = str(data_object["object_type"])

    def by_kind(kind: str, *, different_region: bool = False) -> Mapping[str, Any] | None:
        candidates = [
            database
            for database in databases
            if database["database_kind"] == kind
            and (database["region_id"] != region_id if different_region else database["region_id"] == region_id)
        ]
        return sorted(candidates, key=lambda row: row["database_id"])[0] if candidates else None

    if role == "primary":
        return origin
    if role == "secondary":
        return by_kind(str(origin["database_kind"]), different_region=True) or origin
    if role == "cache":
        return by_kind("model_feature_store") or origin
    if role == "backup":
        return by_kind("archive") or origin
    if role == "export":
        return by_kind("audit") or origin
    if role == "derived":
        return by_kind(OBJECT_PRIMARY_DATABASE_KIND.get(object_type, str(origin["database_kind"]))) or origin
    raise CatalogBuildError(f"unsupported replica role {role!r}")


def _replica_roles_for_object(object_type: str) -> tuple[str, ...]:
    roles = ["primary", "secondary", "backup", "export"]
    if object_type in {"meter_interval", "profile", "model_feature"}:
        roles.append("cache")
    if object_type in DERIVATION_SOURCES or object_type in {"profile", "model_feature"}:
        roles.append("derived")
    return tuple(dict.fromkeys(roles))


def _deletion_due_at(ctx: _CatalogContext, role: str) -> str | None:
    if role in {"cache", "export"}:
        return ctx.resolved.run.horizon_end
    return None


def _deletion_status(role: str, object_type: str) -> str:
    if object_type in {"audit_record", "evidence_record"}:
        return "exempt"
    if role in {"cache", "export"}:
        return "not_due"
    return "not_due"


def _retention_basis_rule_id(ctx: _CatalogContext, data_object: Mapping[str, Any], role: str) -> str:
    profile = _retention_profile(ctx, f"{data_object['object_type']}:{role}")
    return f"RETRULE-{_normalize_token(profile)}-{_normalize_token(str(data_object['object_type']))}-{_normalize_token(role)}"


def _build_replicas(
    ctx: _CatalogContext,
    data_objects: tuple[dict[str, Any], ...],
    databases: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for data_object in data_objects:
        for role in _replica_roles_for_object(str(data_object["object_type"])):
            database = _database_for_role(data_object, databases, role)
            replica_id = deterministic_uuid(
                ctx.namespace,
                "data_object_replica",
                {
                    "scenario_id": ctx.scenario_id,
                    "data_object_id": data_object["data_object_id"],
                    "role": role,
                    "database_id": database["database_id"],
                },
            )
            row = {
                "replica_id": replica_id,
                "data_object_id": data_object["data_object_id"],
                "database_id": database["database_id"],
                "replica_role": role,
                "created_by_event_id": deterministic_uuid(
                    ctx.namespace,
                    "catalog_object_creation_event",
                    {
                        "data_object_id": data_object["data_object_id"],
                        "scenario_id": ctx.scenario_id,
                    },
                ),
                "created_at": ctx.resolved.run.horizon_start,
                "deletion_due_at": _deletion_due_at(ctx, role),
                "deleted_at": None,
                "deletion_status": _deletion_status(role, str(data_object["object_type"])),
                "retention_basis_rule_id": _retention_basis_rule_id(ctx, data_object, role),
            }
            validate_record(ctx.contract, "data_object_replica", row)
            rows.append(row)
    return tuple(sorted(rows, key=lambda row: (row["data_object_id"], row["replica_role"], row["replica_id"])))


def _edge(
    ctx: _CatalogContext,
    *,
    edge_type: str,
    source_id: str,
    target_id: str,
    source_table: str,
    target_table: str,
    reason_code: str,
) -> CustodyEdge:
    edge_id = deterministic_uuid(
        ctx.namespace,
        "custody_edge",
        {
            "edge_type": edge_type,
            "source_id": source_id,
            "target_id": target_id,
            "source_table": source_table,
            "target_table": target_table,
            "scenario_id": ctx.scenario_id,
            "reason_code": reason_code,
        },
    )
    return CustodyEdge(
        edge_id=edge_id,
        scenario_id=ctx.scenario_id,
        edge_type=edge_type,
        source_id=source_id,
        target_id=target_id,
        source_table=source_table,
        target_table=target_table,
        reason_code=reason_code,
    )


def _build_custody_edges(
    ctx: _CatalogContext,
    databases: tuple[dict[str, Any], ...],
    data_objects: tuple[dict[str, Any], ...],
    replicas: tuple[dict[str, Any], ...],
) -> tuple[CustodyEdge, ...]:
    edges: list[CustodyEdge] = []
    objects_by_type_region: dict[tuple[str, str], dict[str, Any]] = {}
    database_by_id = {row["database_id"]: row for row in databases}
    for data_object in data_objects:
        region_id = str(database_by_id[data_object["origin_database_id"]]["region_id"])
        objects_by_type_region[(str(data_object["object_type"]), region_id)] = data_object
        edges.append(
            _edge(
                ctx,
                edge_type="originates_in",
                source_id=str(data_object["origin_database_id"]),
                target_id=str(data_object["data_object_id"]),
                source_table="local_database",
                target_table="data_object",
                reason_code="origin_database",
            )
        )
    for replica in replicas:
        edges.append(
            _edge(
                ctx,
                edge_type="replicated_to",
                source_id=str(replica["data_object_id"]),
                target_id=str(replica["replica_id"]),
                source_table="data_object",
                target_table="data_object_replica",
                reason_code=str(replica["replica_role"]),
            )
        )
    for data_object in data_objects:
        target_type = str(data_object["object_type"])
        origin_region = str(database_by_id[data_object["origin_database_id"]]["region_id"])
        for source_type in DERIVATION_SOURCES.get(target_type, ()):
            source = objects_by_type_region.get((source_type, origin_region))
            if source is None:
                continue
            edges.append(
                _edge(
                    ctx,
                    edge_type="derived_from",
                    source_id=str(source["data_object_id"]),
                    target_id=str(data_object["data_object_id"]),
                    source_table="data_object",
                    target_table="data_object",
                    reason_code=f"{source_type}_to_{target_type}",
                )
            )
    return tuple(sorted(edges, key=lambda edge: edge.edge_id))


def _counts_by(rows: Iterable[Mapping[str, Any]], field_name: str) -> Mapping[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row[field_name])
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _replica_counts(replicas: Iterable[Mapping[str, Any]]) -> Mapping[str, int]:
    return _counts_by(replicas, "replica_role")


def _diagnostics(
    scenario_id: str,
    databases: tuple[dict[str, Any], ...],
    data_objects: tuple[dict[str, Any], ...],
    replicas: tuple[dict[str, Any], ...],
    edges: tuple[CustodyEdge, ...],
) -> CatalogDiagnostics:
    return CatalogDiagnostics(
        scenario_id=scenario_id,
        local_database_count=len(databases),
        data_object_count=len(data_objects),
        replica_count=len(replicas),
        custody_edge_count=len(edges),
        database_counts_by_kind=_counts_by(databases, "database_kind"),
        object_counts_by_type=_counts_by(data_objects, "object_type"),
        replica_counts_by_role=_replica_counts(replicas),
    )


def build_catalog(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> CatalogBuild:
    """Build schema-valid S03 catalog and custody tables."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise CatalogBuildError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise CatalogBuildError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise CatalogBuildError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
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
    validate_catalog_world(world_build, selected)

    all_databases: list[dict[str, Any]] = []
    all_objects: list[dict[str, Any]] = []
    all_replicas: list[dict[str, Any]] = []
    all_edges: list[CustodyEdge] = []
    diagnostics: dict[str, CatalogDiagnostics] = {}

    for scenario_id in sorted(selected):
        ctx = _catalog_context(resolved, scenario_id, replicate_id, world_build, schema_contract)
        databases = _build_local_databases(ctx)
        data_objects = _build_data_objects(ctx, databases)
        replicas = _build_replicas(ctx, data_objects, databases)
        edges = _build_custody_edges(ctx, databases, data_objects, replicas)
        partial = CatalogBuild(
            local_databases=databases,
            data_objects=data_objects,
            data_object_replicas=replicas,
            custody_edges=edges,
            diagnostics={scenario_id: _diagnostics(scenario_id, databases, data_objects, replicas, edges)},
        )
        validate_catalog(partial, resolved, world=world_build, contract=schema_contract, scenario_ids=(scenario_id,))
        all_databases.extend(databases)
        all_objects.extend(data_objects)
        all_replicas.extend(replicas)
        all_edges.extend(edges)
        diagnostics[scenario_id] = partial.diagnostics[scenario_id]

    return CatalogBuild(
        local_databases=tuple(sorted(all_databases, key=lambda row: (row["scenario_id"], row["database_id"]))),
        data_objects=tuple(sorted(all_objects, key=lambda row: (row["scenario_id"], row["data_object_id"]))),
        data_object_replicas=tuple(sorted(all_replicas, key=lambda row: (row["data_object_id"], row["replica_id"]))),
        custody_edges=tuple(sorted(all_edges, key=lambda edge: edge.edge_id)),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def validate_catalog_world(world: FederatedWorld, scenario_ids: Iterable[str]) -> None:
    selected = tuple(scenario_ids)
    for scenario_id in selected:
        if not any(row["scenario_id"] == scenario_id for row in world.actors):
            raise CatalogBuildError(f"{scenario_id}: world has no actors")
        if not any(row["scenario_id"] == scenario_id for row in world.prosumer_cohorts):
            raise CatalogBuildError(f"{scenario_id}: world has no cohorts")
        if not any(row["scenario_id"] == scenario_id for row in world.network_areas):
            raise CatalogBuildError(f"{scenario_id}: world has no network areas")


def _validate_temporal(row: Mapping[str, Any], start_field: str, end_field: str | None, label: str) -> None:
    start = _timestamp(str(row[start_field]))
    if end_field is not None and row.get(end_field) is not None and _timestamp(str(row[end_field])) < start:
        raise CatalogBuildError(f"{label}: {end_field} earlier than {start_field}")


def validate_catalog(
    catalog: CatalogBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    contract: ContractSpec | None = None,
    scenario_ids: Iterable[str] | None = None,
) -> None:
    """Fail closed on S03 schema, FK, lifecycle, closure, and coverage errors."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    validate_catalog_world(world, selected)

    actor_ids = {row["actor_id"] for row in world.actors}
    cohort_ids = {(row["scenario_id"], row["cohort_id"]) for row in world.prosumer_cohorts}
    database_by_id = {row["database_id"]: row for row in catalog.local_databases}
    object_by_id = {row["data_object_id"]: row for row in catalog.data_objects}
    replica_by_id = {row["replica_id"]: row for row in catalog.data_object_replicas}

    if len(database_by_id) != len(catalog.local_databases):
        raise CatalogBuildError("duplicate database_id values")
    if len(object_by_id) != len(catalog.data_objects):
        raise CatalogBuildError("duplicate data_object_id values")
    if len(replica_by_id) != len(catalog.data_object_replicas):
        raise CatalogBuildError("duplicate replica_id values")

    for row in catalog.local_databases:
        validate_record(schema_contract, "local_database", row)
        if row["controller_actor_id"] not in actor_ids:
            raise CatalogBuildError(f"database {row['database_id']}: unresolved controller_actor_id")
        if row["operator_actor_id"] is not None and row["operator_actor_id"] not in actor_ids:
            raise CatalogBuildError(f"database {row['database_id']}: unresolved operator_actor_id")
        if int(row["represented_record_count"]) < 0:
            raise CatalogBuildError(f"database {row['database_id']}: negative represented_record_count")
        if row["capacity_records"] is not None and int(row["capacity_records"]) < int(row["represented_record_count"]):
            raise CatalogBuildError(f"database {row['database_id']}: capacity below represented records")

    for row in catalog.data_objects:
        validate_record(schema_contract, "data_object", row)
        if row["origin_database_id"] not in database_by_id:
            raise CatalogBuildError(f"object {row['data_object_id']}: unresolved origin database")
        if row["subject_cohort_id"] is not None and (row["scenario_id"], row["subject_cohort_id"]) not in cohort_ids:
            raise CatalogBuildError(f"object {row['data_object_id']}: unresolved subject cohort")
        _validate_temporal(row, "created_at", None, f"object {row['data_object_id']}")
        _validate_temporal(row, "valid_from", "valid_to", f"object {row['data_object_id']}")
        database = database_by_id[row["origin_database_id"]]
        if row["object_type"] not in database["supported_object_types"]:
            raise CatalogBuildError(
                f"object {row['data_object_id']}: origin database does not support {row['object_type']}"
            )
        if not row["schema_id"]:
            raise CatalogBuildError(f"object {row['data_object_id']}: schema_id is required")

    roles_by_object: dict[str, set[str]] = {}
    for row in catalog.data_object_replicas:
        validate_record(schema_contract, "data_object_replica", row)
        if row["data_object_id"] not in object_by_id:
            raise CatalogBuildError(f"replica {row['replica_id']}: unresolved data_object_id")
        if row["database_id"] not in database_by_id:
            raise CatalogBuildError(f"replica {row['replica_id']}: unresolved database_id")
        _validate_temporal(row, "created_at", "deletion_due_at", f"replica {row['replica_id']}")
        if row["deleted_at"] is not None and row["deletion_due_at"] is not None:
            if _timestamp(str(row["deleted_at"])) < _timestamp(str(row["created_at"])):
                raise CatalogBuildError(f"replica {row['replica_id']}: deleted before created")
        roles_by_object.setdefault(str(row["data_object_id"]), set()).add(str(row["replica_role"]))

    for data_object_id, roles in roles_by_object.items():
        if "primary" not in roles:
            raise CatalogBuildError(f"object {data_object_id}: missing primary replica")
    if set(REQUIRED_REPLICA_ROLES) - {row["replica_role"] for row in catalog.data_object_replicas}:
        raise CatalogBuildError("catalog does not cover every required replica role")

    valid_ids = set(database_by_id) | set(object_by_id) | set(replica_by_id)
    for edge in catalog.custody_edges:
        if edge.source_id not in valid_ids:
            raise CatalogBuildError(f"custody edge {edge.edge_id}: unresolved source")
        if edge.target_id not in valid_ids:
            raise CatalogBuildError(f"custody edge {edge.edge_id}: unresolved target")

    for scenario_id in selected:
        objects = [row for row in catalog.data_objects if row["scenario_id"] == scenario_id]
        observed_types = {str(row["object_type"]) for row in objects}
        if set(REQUIRED_OBJECT_TYPES) - observed_types:
            raise CatalogBuildError(
                f"{scenario_id}: missing object types {sorted(set(REQUIRED_OBJECT_TYPES) - observed_types)}"
            )
        if not any(edge.edge_type == "derived_from" for edge in catalog.custody_edges if edge.scenario_id == scenario_id):
            raise CatalogBuildError(f"{scenario_id}: missing derivation custody edges")
