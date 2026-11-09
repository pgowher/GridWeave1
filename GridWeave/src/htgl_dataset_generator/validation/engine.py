"""S13 joint validation executor and fail-closed release eligibility gate."""

from __future__ import annotations

from datetime import datetime
import hashlib
import math
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.anomalies import validate_anomaly_build
from htgl_dataset_generator.arrivals import validate_arrivals
from htgl_dataset_generator.catalog import validate_catalog
from htgl_dataset_generator.config import ResolvedRunPlan, build_run_plan
from htgl_dataset_generator.dag import validate_causal_dag
from htgl_dataset_generator.evidence import (
    load_obligation_template_bundle,
    load_receipt_profile_bundle,
    validate_evidence_obligations,
    verify_evidence_receipts,
)
from htgl_dataset_generator.observers import (
    load_observer_profile_bundle,
    validate_observer_build,
)
from htgl_dataset_generator.physical import validate_physical_raw
from htgl_dataset_generator.policy import SafePolicyEvaluator, load_policy_package, validate_policy_oracle
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import canonical_records_digest
from htgl_dataset_generator.sampling import validate_sampling_build
from htgl_dataset_generator.workflows import validate_workflows
from htgl_dataset_generator.world import validate_federated_world

from .models import (
    ArtifactVerificationInput,
    CheckOutcome,
    RegisteredValidationCheck,
    ValidationBuild,
    ValidationInput,
)
from .profiles import ValidationThresholdProfile, load_validation_threshold_profile
from .registry import build_check_registry


PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"
NOT_EXECUTED = "not_executed"
JUSTIFICATION_PREFIX = "justification_code="


EXPECTED_S00_S12_TABLES = frozenset(
    {
        "run_scenario",
        "seed_stream",
        "actor",
        "actor_relationship",
        "prosumer_cohort",
        "network_area",
        "local_database",
        "data_object",
        "data_object_replica",
        "raw_meter_reading",
        "raw_der_telemetry",
        "raw_network_state",
        "raw_context_event",
        "arrival",
        "governance_event",
        "event_edge",
        "workflow_instance",
        "policy_rule",
        "policy_decision_truth",
        "anomaly_instance",
        "evidence_obligation",
        "evidence_receipt",
        "observer_event",
        "sampling_design",
        "sample_membership",
        "run_metric",
    }
)


PRIMARY_KEYS: Mapping[str, tuple[str, ...]] = {
    "run_scenario": ("run_id", "scenario_id", "replicate_id"),
    "seed_stream": ("run_id", "stream_name"),
    "actor": ("actor_id",),
    "actor_relationship": ("relationship_id",),
    "prosumer_cohort": ("cohort_id",),
    "network_area": ("network_area_id",),
    "local_database": ("database_id",),
    "data_object": ("data_object_id",),
    "data_object_replica": ("replica_id",),
    "raw_meter_reading": ("reading_id",),
    "raw_der_telemetry": ("telemetry_id",),
    "raw_network_state": ("network_state_id",),
    "raw_context_event": ("context_event_id",),
    "arrival": ("arrival_id",),
    "governance_event": ("event_id",),
    "event_edge": ("edge_id",),
    "workflow_instance": ("workflow_instance_id",),
    "policy_rule": ("policy_rule_id",),
    "policy_decision_truth": ("decision_id",),
    "anomaly_instance": ("anomaly_instance_id",),
    "evidence_obligation": ("obligation_id",),
    "evidence_receipt": ("receipt_id",),
    "observer_event": ("observer_record_id",),
    "sampling_design": ("sample_design_id",),
    "sample_membership": ("sample_design_id", "unit_type", "unit_id"),
    "run_metric": ("metric_id",),
    "artifact_manifest": ("artifact_id",),
    "validation_issue": ("run_id", "check_id"),
}


class JointValidationError(ValueError):
    """Raised when the S13 executor or release gate cannot fail closed."""


class ValidationCheckFailure(ValueError):
    """Structured failure reported by an independently executed check."""

    def __init__(
        self,
        message: str,
        *,
        affected_record_ids: Iterable[str] = (),
        observed_value: str | None = None,
    ) -> None:
        super().__init__(message)
        self.affected_record_ids = tuple(str(value) for value in affected_record_ids)
        self.observed_value = observed_value


def build_run_scenario_record(
    resolved: Any,
    run_plan: ResolvedRunPlan,
    *,
    contract: ContractSpec | None = None,
) -> dict[str, Any]:
    """Materialize the previously implicit S00 run/scenario/replicate contract."""

    schema_contract = contract if contract is not None else load_contract()
    row = {
        "run_id": run_plan.run_id,
        "scenario_id": run_plan.scenario_id,
        "replicate_id": run_plan.replicate_id,
        "contract_version": resolved.run.contract_version,
        "profile_name": run_plan.scenario_id,
        "start_time": resolved.run.horizon_start,
        "end_time": resolved.run.horizon_end,
        "represented_population": resolved.claim_scale.represented_population,
        "materialized_row_target": resolved.claim_scale.materialized_row_target,
        "executed_operation_target": resolved.claim_scale.executed_operation_target,
        "calibration_profile_id": resolved.run.calibration_profile_id,
        "policy_profile_id": resolved.run.policy_profile_id,
        "publication_derived": False,
        "config_sha256": resolved.config_sha256,
    }
    validate_record(schema_contract, "run_scenario", row)
    return row


def build_joint_validation(
    validation_input: ValidationInput,
    *,
    extensions: Iterable[RegisteredValidationCheck] = (),
    contract: ContractSpec | None = None,
) -> ValidationBuild:
    """Execute every required check, then materialize the complete issue registry."""

    schema_contract = contract if contract is not None else load_contract()
    profile = load_validation_threshold_profile(
        validation_input.resolved.validation.metric_threshold_profile_id
    )
    runners = _core_runners(profile, schema_contract)
    specs, registered_runners = build_check_registry(
        runners,
        required_check_ids=validation_input.resolved.validation.required_check_ids,
        extensions=extensions,
    )
    required = tuple(validation_input.resolved.validation.required_check_ids)
    outcomes: dict[str, CheckOutcome] = {}

    # Do not append validation rows while checks execute. Finalization below
    # compares the complete expected registry to the complete outcome ledger.
    for check_id in sorted(specs):
        runner = registered_runners.get(check_id)
        if runner is None:
            outcomes[check_id] = _not_executed(
                f"no validator implementation is registered for required check {check_id}"
            )
            continue
        try:
            outcome = runner(validation_input)
            _validate_outcome(check_id, outcome)
        except ValidationCheckFailure as exc:
            outcome = CheckOutcome(
                status=FAIL,
                observed_value=exc.observed_value or type(exc).__name__,
                affected_record_ids=exc.affected_record_ids,
                message=str(exc),
            )
        except Exception as exc:
            outcome = CheckOutcome(
                status=FAIL,
                observed_value=type(exc).__name__,
                affected_record_ids=(),
                message=str(exc) or repr(exc),
            )
        outcomes[check_id] = outcome

    if set(outcomes) != set(specs):
        missing = sorted(set(specs) - set(outcomes))
        extra = sorted(set(outcomes) - set(specs))
        raise JointValidationError(f"validation outcome ledger mismatch missing={missing} extra={extra}")

    rows: list[dict[str, Any]] = []
    for check_id in sorted(specs):
        spec = specs[check_id]
        outcome = outcomes[check_id]
        row = {
            "check_id": check_id,
            "run_id": validation_input.run_plan.run_id,
            "severity": spec.severity,
            "domain": spec.domain,
            "status": outcome.status,
            "observed_value": outcome.observed_value,
            "expected_condition": spec.expected_condition,
            "affected_record_ids": list(
                outcome.affected_record_ids[: profile.max_affected_record_ids]
            ),
            "message": outcome.message,
            "validator_version": spec.validator_version,
        }
        validate_record(schema_contract, "validation_issue", row)
        rows.append(row)

    release_eligible = validation_issues_are_release_eligible(rows, required)
    return ValidationBuild(
        validation_issues=tuple(rows),
        required_check_ids=required,
        executed_check_ids=tuple(
            sorted(check_id for check_id, item in outcomes.items() if item.status != NOT_EXECUTED)
        ),
        release_eligible=release_eligible,
        threshold_profile_id=profile.profile_id,
        threshold_profile_sha256=profile.profile_sha256,
    )


def validation_issues_are_release_eligible(
    issues: Sequence[Mapping[str, Any]],
    required_check_ids: Iterable[str],
) -> bool:
    """Return true only when the complete required registry is publication-safe."""

    required = set(required_check_ids)
    by_id: dict[str, Mapping[str, Any]] = {}
    for row in issues:
        check_id = str(row.get("check_id", ""))
        if check_id in by_id:
            return False
        by_id[check_id] = row
    if not required <= set(by_id):
        return False
    for check_id in required:
        row = by_id[check_id]
        status = str(row.get("status"))
        if status == PASS:
            continue
        if status == NOT_APPLICABLE and _has_explicit_justification(row):
            continue
        return False
    return True


def require_validation_release(build: ValidationBuild) -> None:
    """Refuse release packaging unless every required S13 check is resolved."""

    if build.release_eligible:
        return
    unresolved = [
        f"{row['check_id']}={row['status']}"
        for row in build.validation_issues
        if row["check_id"] in build.required_check_ids
        and not (
            row["status"] == PASS
            or (row["status"] == NOT_APPLICABLE and _has_explicit_justification(row))
        )
    ]
    raise JointValidationError(
        "release packaging refused; unresolved required validation checks: "
        + ", ".join(unresolved)
    )


def _core_runners(
    profile: ValidationThresholdProfile,
    contract: ContractSpec,
) -> Mapping[str, Any]:
    return {
        "SCHEMA-001": lambda data: _check_schema(data, contract),
        "IDENTITY-001": _check_identity,
        "FK-001": lambda data: _check_foreign_keys(data, contract),
        "TEMPORAL-001": _check_temporal,
        "PHYSICAL-001": lambda data: _check_physical(data, contract),
        "TEMPORAL-ARRIVAL-001": lambda data: _check_arrivals(data, contract),
        "WORKFLOW-001": lambda data: _check_workflows(data, contract),
        "DAG-001": lambda data: _check_dag(data, contract),
        "POLICY-001": lambda data: _check_policy(data, contract),
        "ANOMALY-001": lambda data: _check_anomalies(data, contract),
        "EVIDENCE-001": lambda data: _check_evidence(data, contract),
        "OBSERVER-001": lambda data: _check_observers(data, contract),
        "SAMPLING-001": lambda data: _check_sampling(data, contract),
        "N-N-Q-001": _check_scale_semantics,
        "PRIVACY-001": _check_privacy,
        "PRIVACY-SOURCE-001": _check_source_privacy,
        "RECONCILIATION-001": _check_reconciliation,
        "REPLICATE-001": _check_replicates,
        "MANIFEST-001": lambda data: _check_manifest(data, contract),
        "REPRODUCIBILITY-001": _check_reproducibility,
        "PERFORMANCE-001": lambda data: _check_performance(data, profile),
    }


def _check_schema(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    missing = sorted(EXPECTED_S00_S12_TABLES - set(data.tables))
    if missing:
        raise ValidationCheckFailure(
            f"implemented S00-S12 table set is incomplete: {missing}",
            affected_record_ids=missing,
            observed_value=f"missing_tables={len(missing)}",
        )
    record_count = 0
    for table_name, rows in sorted(data.tables.items()):
        if table_name not in contract.table_names:
            raise ValidationCheckFailure(
                f"unknown authoritative table {table_name}", affected_record_ids=(table_name,)
            )
        for index, row in enumerate(rows):
            try:
                validate_record(contract, table_name, row)
            except Exception as exc:
                raise ValidationCheckFailure(
                    f"{table_name}[{index}] violates the locked schema: {exc}",
                    affected_record_ids=(_record_identifier(table_name, row, index),),
                ) from exc
            record_count += 1
    return _passed(f"tables={len(data.tables)};records={record_count}")


def _check_identity(data: ValidationInput) -> CheckOutcome:
    checked = 0
    for table_name, rows in sorted(data.tables.items()):
        fields = PRIMARY_KEYS.get(table_name)
        if fields is None:
            raise ValidationCheckFailure(f"no primary-key contract registered for {table_name}")
        seen: set[tuple[Any, ...]] = set()
        for index, row in enumerate(rows):
            key = tuple(row.get(field) for field in fields)
            if any(value is None for value in key):
                raise ValidationCheckFailure(
                    f"{table_name}[{index}] has null primary-key component {fields}",
                    affected_record_ids=(_record_identifier(table_name, row, index),),
                )
            if key in seen:
                raise ValidationCheckFailure(
                    f"{table_name} contains duplicate primary key {key}",
                    affected_record_ids=("|".join(str(value) for value in key),),
                )
            seen.add(key)
            checked += 1
    return _passed(f"unique_primary_keys={checked}")


def _check_foreign_keys(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_federated_world(data.world, data.resolved, contract=contract)
    validate_catalog(data.catalog, data.resolved, world=data.world, contract=contract)
    tables = data.tables
    indexes = {
        table: _id_set(tables, table, field)
        for table, field in (
            ("run_scenario", "run_id"),
            ("actor", "actor_id"),
            ("prosumer_cohort", "cohort_id"),
            ("network_area", "network_area_id"),
            ("local_database", "database_id"),
            ("data_object", "data_object_id"),
            ("data_object_replica", "replica_id"),
            ("raw_context_event", "context_event_id"),
            ("arrival", "arrival_id"),
            ("governance_event", "event_id"),
            ("workflow_instance", "workflow_instance_id"),
            ("policy_rule", "policy_rule_id"),
            ("evidence_obligation", "obligation_id"),
            ("sampling_design", "sample_design_id"),
        )
    }
    references: list[tuple[str, str, str, set[str], bool]] = [
        ("actor_relationship", "source_actor_id", "actor", indexes["actor"], False),
        ("actor_relationship", "target_actor_id", "actor", indexes["actor"], False),
        ("network_area", "parent_network_area_id", "network_area", indexes["network_area"], True),
        ("network_area", "controller_actor_id", "actor", indexes["actor"], False),
        ("network_area", "operator_actor_id", "actor", indexes["actor"], True),
        ("local_database", "controller_actor_id", "actor", indexes["actor"], False),
        ("local_database", "operator_actor_id", "actor", indexes["actor"], True),
        ("data_object", "origin_database_id", "local_database", indexes["local_database"], False),
        ("data_object", "subject_cohort_id", "prosumer_cohort", indexes["prosumer_cohort"], True),
        ("data_object_replica", "data_object_id", "data_object", indexes["data_object"], False),
        ("data_object_replica", "database_id", "local_database", indexes["local_database"], False),
        ("data_object_replica", "created_by_event_id", "governance_event", indexes["governance_event"], True),
        ("raw_meter_reading", "cohort_id", "prosumer_cohort", indexes["prosumer_cohort"], False),
        ("raw_der_telemetry", "trigger_event_id", "raw_context_event", indexes["raw_context_event"], True),
        ("arrival", "subject_cohort_id", "prosumer_cohort", indexes["prosumer_cohort"], False),
        ("arrival", "parent_arrival_id", "arrival", indexes["arrival"], True),
        ("governance_event", "source_event_id", "event_or_arrival", indexes["governance_event"] | indexes["arrival"], True),
        ("governance_event", "subject_cohort_id", "prosumer_cohort", indexes["prosumer_cohort"], True),
        ("governance_event", "local_database_id", "local_database", indexes["local_database"], False),
        ("governance_event", "data_object_id", "data_object", indexes["data_object"], False),
        ("governance_event", "workflow_instance_id", "workflow_instance", indexes["workflow_instance"], False),
        ("governance_event", "root_event_id", "governance_event", indexes["governance_event"], False),
        ("event_edge", "source_event_id", "governance_event", indexes["governance_event"], False),
        ("event_edge", "target_event_id", "governance_event", indexes["governance_event"], False),
        ("workflow_instance", "root_event_id", "governance_event", indexes["governance_event"], False),
        ("workflow_instance", "terminal_event_id", "governance_event", indexes["governance_event"], True),
        ("policy_decision_truth", "event_id", "governance_event", indexes["governance_event"], False),
        ("evidence_obligation", "event_id", "governance_event", indexes["governance_event"], False),
        ("evidence_obligation", "policy_rule_id", "policy_rule", indexes["policy_rule"], False),
        ("evidence_obligation", "subject_object_id", "data_object", indexes["data_object"], False),
        ("evidence_obligation", "responsible_actor_id", "actor", indexes["actor"], False),
        ("evidence_receipt", "obligation_id", "evidence_obligation", indexes["evidence_obligation"], False),
        ("evidence_receipt", "event_id", "governance_event", indexes["governance_event"], False),
        ("evidence_receipt", "issuer_actor_id", "actor", indexes["actor"], False),
        ("observer_event", "observer_actor_id", "actor", indexes["actor"], False),
        ("observer_event", "source_event_id", "governance_event", indexes["governance_event"], False),
        ("sample_membership", "sample_design_id", "sampling_design", indexes["sampling_design"], False),
        ("run_metric", "run_id", "run_scenario", indexes["run_scenario"], False),
    ]
    actor_fields = (
        "source_actor_id",
        "requesting_actor_id",
        "controller_actor_id",
        "processor_actor_id",
        "oversight_actor_id",
    )
    references.extend(
        ("governance_event", field, "actor", indexes["actor"], field != "source_actor_id")
        for field in actor_fields
    )
    checked = 0
    for table_name, field, target, allowed, nullable in references:
        for index, row in enumerate(tables.get(table_name, ())):
            value = row.get(field)
            if value is None and nullable:
                continue
            if value is None or str(value) not in allowed:
                raise ValidationCheckFailure(
                    f"{table_name}.{field}={value!r} does not resolve to {target}",
                    affected_record_ids=(_record_identifier(table_name, row, index),),
                )
            checked += 1
    for row in tables.get("policy_decision_truth", ()):
        unknown = sorted(set(str(item) for item in row["applied_rule_ids"]) - indexes["policy_rule"])
        if unknown:
            raise ValidationCheckFailure(
                f"policy decision has unknown applied rules {unknown}",
                affected_record_ids=(str(row["decision_id"]),),
            )
    for row in tables.get("evidence_receipt", ()):
        unknown = sorted(set(str(item) for item in row["covers_replica_ids"]) - indexes["data_object_replica"])
        if unknown:
            raise ValidationCheckFailure(
                f"receipt covers unresolved replicas {unknown}",
                affected_record_ids=(str(row["receipt_id"]),),
            )
    provenance_keys = {
        (item.sample_design_id, item.unit_type, item.unit_id)
        for item in data.sampling.closure_provenance
    }
    for row in tables.get("sample_membership", ()):
        key = (str(row["sample_design_id"]), str(row["unit_type"]), str(row["unit_id"]))
        if key not in provenance_keys:
            raise ValidationCheckFailure(
                f"sample membership has no closure provenance {key}",
                affected_record_ids=("|".join(key),),
            )
    return _passed(f"resolved_references={checked}")


def _check_temporal(data: ValidationInput) -> CheckOutcome:
    tables = data.tables
    interval_fields = (
        ("run_scenario", "start_time", "end_time", False),
        ("actor", "valid_from", "valid_to", True),
        ("actor_relationship", "valid_from", "valid_to", True),
        ("network_area", "valid_from", "valid_to", True),
        ("data_object", "valid_from", "valid_to", True),
        ("raw_meter_reading", "interval_start", "interval_end", False),
        ("raw_context_event", "start_time", "end_time", True),
        ("workflow_instance", "started_at", "ended_at", True),
        ("anomaly_instance", "start_time", "end_time", False),
        ("policy_rule", "effective_from", "effective_to", True),
    )
    checked = 0
    for table_name, start_field, end_field, nullable_end in interval_fields:
        for index, row in enumerate(tables.get(table_name, ())):
            start = _timestamp(row[start_field])
            end_raw = row[end_field]
            if end_raw is None and nullable_end:
                checked += 1
                continue
            if end_raw is None or _timestamp(end_raw) < start:
                raise ValidationCheckFailure(
                    f"{table_name} has {end_field} before {start_field}",
                    affected_record_ids=(_record_identifier(table_name, row, index),),
                )
            checked += 1
    event_by_id = {str(row["event_id"]): row for row in tables.get("governance_event", ())}
    for edge in tables.get("event_edge", ()):
        source = event_by_id[str(edge["source_event_id"])]
        target = event_by_id[str(edge["target_event_id"])]
        if str(edge["edge_type"]) == "precedes" and _timestamp(source["timestamp"]) > _timestamp(target["timestamp"]):
            raise ValidationCheckFailure(
                "precedes edge reverses event timestamps",
                affected_record_ids=(str(edge["edge_id"]),),
            )
    for replica in tables.get("data_object_replica", ()):
        created = _timestamp(replica["created_at"])
        due = replica["deletion_due_at"]
        deleted = replica["deleted_at"]
        if due is not None and _timestamp(due) < created:
            raise ValidationCheckFailure(
                "replica deletion_due_at precedes creation", affected_record_ids=(str(replica["replica_id"]),)
            )
        if deleted is not None and _timestamp(deleted) < created:
            raise ValidationCheckFailure(
                "replica deleted_at precedes creation", affected_record_ids=(str(replica["replica_id"]),)
            )
    return _passed(f"temporal_intervals={checked}")


def _check_physical(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_physical_raw(data.physical, data.resolved, world=data.world, contract=contract)
    issue_count = sum(item.validation_issue_count for item in data.physical.diagnostics.values())
    if issue_count:
        raise ValidationCheckFailure(
            "physical diagnostics contain validation issues", observed_value=f"issues={issue_count}"
        )
    return _passed(f"physical_rows={sum(len(rows) for rows in data.physical.table_records().values())}")


def _check_arrivals(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_arrivals(data.arrivals, data.resolved, world=data.world, catalog=data.catalog, contract=contract)
    failed = [key for key, item in data.arrivals.diagnostics.items() if not item.passed]
    if failed:
        raise ValidationCheckFailure("arrival diagnostics failed", affected_record_ids=failed)
    return _passed(f"arrival_diagnostics={len(data.arrivals.diagnostics)}")


def _check_workflows(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_workflows(
        data.workflows,
        data.resolved,
        arrivals=data.arrivals,
        catalog=data.catalog,
        contract=contract,
    )
    original = {str(row["event_id"]): row for row in data.workflows.governance_events}
    finalized = {str(row["event_id"]): row for row in data.causal_dag.governance_events}
    if set(original) != set(finalized):
        raise ValidationCheckFailure("S06 and S07 governance event identities do not reconcile")
    dag_derived_fields = {"root_event_id", "causal_depth"}
    for event_id in sorted(original):
        original_semantics = {
            key: value for key, value in original[event_id].items() if key not in dag_derived_fields
        }
        finalized_semantics = {
            key: value for key, value in finalized[event_id].items() if key not in dag_derived_fields
        }
        if original_semantics != finalized_semantics:
            raise ValidationCheckFailure(
                "S07 changed non-DAG workflow transition semantics",
                affected_record_ids=(event_id,),
            )
    return _passed(f"workflows={len(data.workflows.workflow_instances)}")


def _check_dag(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_causal_dag(data.causal_dag, data.resolved, contract=contract)
    return _passed(f"edges={len(data.causal_dag.event_edges)};closures={len(data.causal_dag.closure_index)}")


def _check_policy(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    package = load_policy_package(data.resolved, contract=contract)
    validate_policy_oracle(
        data.policy,
        data.resolved,
        world=data.world,
        catalog=data.catalog,
        causal_dag=data.causal_dag,
        package=package,
        evaluator=SafePolicyEvaluator(package),
        replicate_id=data.run_plan.replicate_id,
        scenario_ids=(data.run_plan.scenario_id,),
        contract=contract,
    )
    return _passed(f"decisions={len(data.policy.policy_decisions)};golden_cases={data.policy.golden_result.case_count}")


def _check_anomalies(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_anomaly_build(data.anomalies, data.resolved, contract=contract)
    return _passed(f"accepted_anomalies={len(data.anomalies.anomaly_instances)}")


def _check_evidence(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    package = load_policy_package(data.resolved, contract=contract)
    bundle = load_obligation_template_bundle(data.resolved, package, contract=contract)
    validate_evidence_obligations(
        data.obligations,
        data.resolved,
        world=data.world,
        catalog=data.catalog,
        workflows=data.workflows,
        causal_dag=data.causal_dag,
        policy=data.policy,
        policy_package=package,
        bundle=bundle,
        replicate_id=data.run_plan.replicate_id,
        scenario_ids=(data.run_plan.scenario_id,),
        contract=contract,
    )
    profile_bundle = load_receipt_profile_bundle(data.resolved, contract=contract)
    recomputed = verify_evidence_receipts(
        data.resolved,
        data.receipts.evidence_receipts,
        data.receipts.receipt_fixtures,
        data.receipts.synthetic_keys,
        data.receipts.synthetic_anchors,
        data.obligations,
        world=data.world,
        catalog=data.catalog,
        causal_dag=data.causal_dag,
        replicate_id=data.run_plan.replicate_id,
        scenario_ids=(data.run_plan.scenario_id,),
        profile_bundle=profile_bundle,
        contract=contract,
        require_truth_match=True,
    )
    if recomputed != data.receipts.verification:
        raise ValidationCheckFailure("stored evidence verification truth differs from independent recomputation")
    return _passed(
        f"obligations={len(data.obligations.evidence_obligations)};receipts={len(data.receipts.evidence_receipts)}"
    )


def _check_observers(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    bundle = load_observer_profile_bundle(data.resolved, contract=contract)
    validate_observer_build(
        data.observers,
        data.resolved,
        world=data.world,
        causal_dag=data.causal_dag,
        bundle=bundle,
        scenario_ids=(data.run_plan.scenario_id,),
        contract=contract,
    )
    return _passed(f"observer_records={len(data.observers.observer_events)}")


def _check_sampling(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    validate_sampling_build(data.sampling, data.resolved, contract=contract)
    return _passed(f"designs={len(data.sampling.sampling_designs)};memberships={len(data.sampling.sample_memberships)}")


def _check_scale_semantics(data: ValidationInput) -> CheckOutcome:
    expected = {
        "represented_population_N": data.resolved.claim_scale.represented_population,
        "materialized_row_target_n": data.resolved.claim_scale.materialized_row_target,
        "executed_operation_target_q": data.resolved.claim_scale.executed_operation_target,
    }
    if dict(data.sampling.scale_semantics) != expected:
        raise ValidationCheckFailure(
            "sampling scale semantics do not match resolved N/n/q",
            observed_value=str(dict(data.sampling.scale_semantics)),
        )
    if expected["executed_operation_target_q"] is None:
        prohibited = [
            str(row["metric_id"])
            for row in data.tables.get("run_metric", ())
            if "executed_operation" in str(row["metric_name"])
        ]
        if prohibited:
            raise ValidationCheckFailure(
                "execution metrics exist although q is undeclared", affected_record_ids=prohibited
            )
    return _passed(f"N={expected['represented_population_N']};n={expected['materialized_row_target_n']};q={expected['executed_operation_target_q']}")


def _check_privacy(data: ValidationInput) -> CheckOutcome:
    leakage = data.observers.leakage_diagnostics
    if not leakage.passed:
        raise ValidationCheckFailure(
            "observer release leakage scan failed",
            affected_record_ids=(item.observer_record_id for item in leakage.findings),
            observed_value=f"findings={len(leakage.findings)}",
        )
    protected_tokens = {
        pair.protected_pair_id for pair in data.anomalies.counterfactual_pairs
    }
    for view in data.observers.release_views.values():
        serialized = "\n".join(str(row) for row in view.records)
        leaked = sorted(token for token in protected_tokens if token and token in serialized)
        if leaked:
            raise ValidationCheckFailure(
                "protected pair identifiers occur in observer release records",
                affected_record_ids=leaked,
            )
    return _passed(f"release_records={sum(len(view.records) for view in data.observers.release_views.values())};leakage=0")


def _check_source_privacy(data: ValidationInput) -> CheckOutcome:
    return CheckOutcome(
        status=NOT_APPLICABLE,
        observed_value="private_source_membership_set=absent",
        affected_record_ids=(),
        message=(
            "justification_code=NO_PRIVATE_SOURCE_MEMBERSHIP; the configured generator uses "
            "controlled synthetic values, calibrated aggregates, or imported templates and does not "
            "ingest an individual-level private source membership set; membership/attribute inference "
            "against such a set is therefore not defined for this run"
        ),
    )


def _check_reconciliation(data: ValidationInput) -> CheckOutcome:
    scenario_id = data.run_plan.scenario_id
    cohort_total = sum(
        int(row["represented_consumer_count"]) + int(row["represented_prosumer_count"])
        for row in data.tables["prosumer_cohort"]
        if str(row["scenario_id"]) == scenario_id
    )
    if cohort_total != data.resolved.claim_scale.represented_population:
        raise ValidationCheckFailure(
            "cohort represented counts do not reconcile to N",
            observed_value=f"cohort_total={cohort_total}",
        )
    arrivals = tuple(
        row for row in data.tables["arrival"] if str(row["scenario_id"]) == scenario_id
    )
    workflows = tuple(
        row for row in data.tables["workflow_instance"] if str(row["scenario_id"]) == scenario_id
    )
    arrival_ids = {str(row["arrival_id"]) for row in arrivals}
    event_by_id = {
        str(row["event_id"]): row for row in data.tables["governance_event"]
    }
    arrival_workflows = tuple(
        row
        for row in workflows
        if str(event_by_id[str(row["root_event_id"])]["source_event_id"]) in arrival_ids
    )
    if len(arrivals) != len(arrival_workflows):
        raise ValidationCheckFailure(
            "arrival and workflow counts do not reconcile",
            observed_value=f"arrivals={len(arrivals)};arrival_workflows={len(arrival_workflows)}",
        )
    root_ids = {str(row["root_event_id"]) for row in arrival_workflows}
    root_events = [row for row in data.tables["governance_event"] if str(row["event_id"]) in root_ids]
    arrival_exposure = sum(float(row["represented_arrival_count"]) for row in arrivals)
    root_exposure = sum(float(row["represented_event_count"]) for row in root_events)
    if not math.isclose(arrival_exposure, root_exposure, rel_tol=1e-12, abs_tol=1e-9):
        raise ValidationCheckFailure(
            "represented arrival exposure does not reconcile to workflow roots",
            observed_value=f"arrivals={arrival_exposure};roots={root_exposure}",
        )
    metric_ids = [str(row["metric_id"]) for row in data.tables["run_metric"]]
    if len(metric_ids) != len(set(metric_ids)):
        raise ValidationCheckFailure("run metrics contain duplicate metric IDs")
    return _passed(
        f"N={cohort_total};arrivals={len(arrivals)};arrival_workflows={len(arrival_workflows)};catalog_workflows={len(workflows) - len(arrival_workflows)}"
    )


def _check_replicates(data: ValidationInput) -> CheckOutcome:
    expected = {
        (plan.scenario_id, plan.replicate_id)
        for plan in build_run_plan(data.resolved)
    }
    observed = {(item.scenario_id, item.replicate_id) for item in data.replicate_evidence}
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ValidationCheckFailure(
            f"replicate evidence mismatch missing={missing} extra={extra}",
            affected_record_ids=(f"{scenario}:{replicate}" for scenario, replicate in missing + extra),
        )
    invalid = [
        f"{item.scenario_id}:{item.replicate_id}"
        for item in data.replicate_evidence
        if len(item.seed_stream_digest) != 64 or item.retained_metric_count <= 0
    ]
    if invalid:
        raise ValidationCheckFailure(
            "replicates lack seed digest or retained per-replicate metrics",
            affected_record_ids=invalid,
        )
    return _passed(f"executed_replicates={len(observed)}")


def _check_manifest(data: ValidationInput, contract: ContractSpec) -> CheckOutcome:
    verification = data.artifact_verification
    if verification is None:
        return _not_executed(
            "final stored artifact bytes and proposed artifact_manifest rows were not supplied; S15 must execute this check before release"
        )
    required_schema_ids = {
        contract.table(table_name).schema_id for table_name in data.tables
    }
    supplied_schema_ids = {
        schema_id
        for schema_id in verification.expected_schema_ids.values()
        if schema_id is not None
    }
    if supplied_schema_ids != required_schema_ids:
        missing = sorted(required_schema_ids - supplied_schema_ids)
        extra = sorted(supplied_schema_ids - required_schema_ids)
        raise ValidationCheckFailure(
            f"manifest authoritative schema coverage mismatch missing={missing} extra={extra}",
            affected_record_ids=missing + extra,
        )
    _verify_artifact_manifest(verification, contract)
    return _passed(f"manifest_artifacts={len(verification.manifest_rows)}")


def _verify_artifact_manifest(
    verification: ArtifactVerificationInput,
    contract: ContractSpec,
) -> None:
    rows_by_path: dict[str, Mapping[str, Any]] = {}
    artifact_ids: set[str] = set()
    for index, raw in enumerate(verification.manifest_rows):
        row = dict(raw)
        try:
            validate_record(contract, "artifact_manifest", row)
        except Exception as exc:
            raise ValidationCheckFailure(
                f"artifact_manifest[{index}] violates schema: {exc}",
                affected_record_ids=(str(row.get("artifact_id", index)),),
            ) from exc
        artifact_id = str(row["artifact_id"])
        path = str(row["relative_path"])
        if artifact_id in artifact_ids:
            raise ValidationCheckFailure("duplicate artifact_id", affected_record_ids=(artifact_id,))
        if path in rows_by_path:
            raise ValidationCheckFailure("duplicate manifest relative_path", affected_record_ids=(path,))
        artifact_ids.add(artifact_id)
        rows_by_path[path] = row
    payload_paths = set(verification.artifact_payloads)
    if set(rows_by_path) != payload_paths:
        missing = sorted(payload_paths - set(rows_by_path))
        extra = sorted(set(rows_by_path) - payload_paths)
        raise ValidationCheckFailure(
            f"manifest path coverage mismatch missing={missing} extra={extra}",
            affected_record_ids=missing + extra,
        )
    if set(verification.expected_record_counts) != payload_paths:
        raise ValidationCheckFailure("expected record-count inventory does not cover exactly the stored payloads")
    if set(verification.expected_schema_ids) != payload_paths:
        raise ValidationCheckFailure("expected schema inventory does not cover exactly the stored payloads")
    for path in sorted(payload_paths):
        payload = verification.artifact_payloads[path]
        row = rows_by_path[path]
        digest = hashlib.sha256(payload).hexdigest()
        if str(row["sha256"]) != digest:
            raise ValidationCheckFailure(
                f"manifest SHA-256 mismatch for {path}", affected_record_ids=(path,)
            )
        if int(row["stored_bytes"]) != len(payload):
            raise ValidationCheckFailure(
                f"manifest stored_bytes mismatch for {path}", affected_record_ids=(path,)
            )
        if int(row["record_count"]) != int(verification.expected_record_counts[path]):
            raise ValidationCheckFailure(
                f"manifest record_count mismatch for {path}", affected_record_ids=(path,)
            )
        if row["schema_id"] != verification.expected_schema_ids[path]:
            raise ValidationCheckFailure(
                f"manifest schema_id mismatch for {path}", affected_record_ids=(path,)
            )
        if row["schema_id"] is not None:
            if row["media_type"] != "application/parquet":
                raise ValidationCheckFailure(
                    f"schema-bound artifact {path} is not declared as Parquet",
                    affected_record_ids=(path,),
                )
            _verify_parquet_payload(
                path,
                payload,
                expected_schema_id=str(row["schema_id"]),
                expected_record_count=int(row["record_count"]),
            )


def _verify_parquet_payload(
    path: str,
    payload: bytes,
    *,
    expected_schema_id: str,
    expected_record_count: int,
) -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ValidationCheckFailure(
            "pyarrow is required to verify authoritative Parquet artifact bytes"
        ) from exc
    try:
        parquet_file = pq.ParquetFile(pa.BufferReader(payload))
    except Exception as exc:
        raise ValidationCheckFailure(
            f"artifact {path} is not a readable Parquet payload",
            affected_record_ids=(path,),
        ) from exc
    try:
        if parquet_file.metadata.num_rows != expected_record_count:
            raise ValidationCheckFailure(
                f"Parquet metadata row count mismatch for {path}",
                affected_record_ids=(path,),
            )
        metadata = parquet_file.schema_arrow.metadata or {}
        schema_id = metadata.get(b"schema_id", b"").decode("utf-8")
        if schema_id != expected_schema_id:
            raise ValidationCheckFailure(
                f"Parquet schema metadata mismatch for {path}",
                affected_record_ids=(path,),
            )
        for row_group_index in range(parquet_file.metadata.num_row_groups):
            row_group = parquet_file.metadata.row_group(row_group_index)
            for column_index in range(row_group.num_columns):
                if row_group.column(column_index).compression != "ZSTD":
                    raise ValidationCheckFailure(
                        f"Parquet column is not ZSTD-compressed for {path}",
                        affected_record_ids=(path,),
                    )
    finally:
        parquet_file.close()


def _check_reproducibility(data: ValidationInput) -> CheckOutcome:
    reference = data.reproducibility_reference_digests
    if reference is None:
        return _not_executed(
            "clean-rerun authoritative table digests were not supplied; release requires a separately executed rerun"
        )
    observed = {
        table_name: canonical_records_digest(rows)
        for table_name, rows in sorted(data.tables.items())
    }
    if dict(reference) != observed:
        mismatched = sorted(
            set(reference) ^ set(observed)
            | {key for key in set(reference) & set(observed) if reference[key] != observed[key]}
        )
        raise ValidationCheckFailure(
            "clean-rerun canonical digests differ", affected_record_ids=mismatched
        )
    return _passed(f"reproduced_table_digests={len(observed)}")


def _check_performance(
    data: ValidationInput,
    profile: ValidationThresholdProfile,
) -> CheckOutcome:
    observation = data.performance_observation
    if observation is None:
        return _not_executed(
            "measured runtime, memory, storage and parallel-efficiency observations were not supplied"
        )
    if observation.measurement_profile_id != profile.profile_id:
        raise ValidationCheckFailure(
            "performance observation profile does not match resolved threshold profile",
            observed_value=observation.measurement_profile_id,
        )
    numeric = (
        observation.elapsed_seconds,
        observation.rows_per_second,
        observation.bytes_per_row,
        observation.parallel_efficiency,
    )
    if any(not math.isfinite(value) or value <= 0 for value in numeric):
        raise ValidationCheckFailure("performance observations must be positive and finite")
    if observation.generated_row_count <= 0 or observation.peak_memory_bytes <= 0 or observation.stored_bytes <= 0:
        raise ValidationCheckFailure("performance counts and byte observations must be positive")
    recomputed_rate = observation.generated_row_count / observation.elapsed_seconds
    recomputed_bytes_per_row = observation.stored_bytes / observation.generated_row_count
    if not math.isclose(observation.rows_per_second, recomputed_rate, rel_tol=1e-9):
        raise ValidationCheckFailure("rows_per_second does not reconcile to rows/elapsed_seconds")
    if not math.isclose(observation.bytes_per_row, recomputed_bytes_per_row, rel_tol=1e-9):
        raise ValidationCheckFailure("bytes_per_row does not reconcile to stored_bytes/rows")
    if observation.requested_worker_count < 1 or observation.effective_worker_count < 1:
        raise ValidationCheckFailure("performance worker counts must be positive")
    if observation.effective_worker_count > observation.requested_worker_count:
        raise ValidationCheckFailure(
            "effective worker count cannot exceed requested worker count"
        )
    if observation.effective_worker_count > 1:
        if observation.serial_elapsed_seconds is None:
            raise ValidationCheckFailure(
                "parallel performance requires separately measured serial elapsed time"
            )
        expected_efficiency = observation.serial_elapsed_seconds / (
            observation.elapsed_seconds * observation.effective_worker_count
        )
        if not math.isclose(
            observation.parallel_efficiency,
            expected_efficiency,
            rel_tol=1e-9,
        ):
            raise ValidationCheckFailure(
                "parallel efficiency does not reconcile to serial/(parallel*workers)"
            )
    if observation.stage_observations:
        required_stages = {
            "S02", "S03", "S04", "S05", "S06", "S07-dag", "S07-policy",
            "S08", "S09", "S10", "S11", "S12", "S13", "S14",
        }
        observed_stages = [item.stage_id for item in observation.stage_observations]
        if len(observed_stages) != len(set(observed_stages)):
            raise ValidationCheckFailure("stage performance contains duplicate stage IDs")
        if set(observed_stages) != required_stages:
            raise ValidationCheckFailure(
                "stage performance coverage is incomplete",
                affected_record_ids=tuple(sorted(required_stages ^ set(observed_stages))),
            )
        for stage in observation.stage_observations:
            if stage.elapsed_seconds <= 0 or not math.isfinite(stage.elapsed_seconds):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: elapsed time must be positive and finite"
                )
            if stage.generated_row_count < 0:
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: generated row count cannot be negative"
                )
            if not math.isclose(
                stage.rows_per_second,
                stage.generated_row_count / stage.elapsed_seconds,
                rel_tol=1e-9,
            ):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: row throughput does not reconcile"
                )
            if stage.peak_resident_memory_bytes < max(
                stage.rss_before_bytes,
                stage.rss_after_bytes,
            ):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: peak RSS is below endpoint RSS"
                )
            if stage.serial_elapsed_seconds is None or stage.serial_elapsed_seconds <= 0:
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: serial stage timing is missing"
                )
            expected_stage_efficiency = stage.serial_elapsed_seconds / (
                stage.elapsed_seconds * observation.effective_worker_count
            )
            if not math.isclose(
                stage.parallel_efficiency,
                expected_stage_efficiency,
                rel_tol=1e-9,
            ):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: parallel efficiency does not reconcile"
                )
            if stage.generated_row_count > 0 and (
                stage.stored_bytes <= 0
                or stage.row_group_count <= 0
                or not stage.artifact_sha256
            ):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: positive-row stage lacks artifact measurement evidence"
                )
            if stage.row_group_efficiency is not None and not (
                0 < stage.row_group_efficiency <= 1
            ):
                raise ValidationCheckFailure(
                    f"{stage.stage_id}: row-group efficiency must be in (0, 1]"
                )
    failures = []
    if observation.rows_per_second < profile.minimum_rows_per_second:
        failures.append("rows_per_second")
    if observation.peak_memory_bytes > profile.maximum_peak_memory_bytes:
        failures.append("peak_memory_bytes")
    if observation.bytes_per_row > profile.maximum_bytes_per_row:
        failures.append("bytes_per_row")
    if observation.parallel_efficiency < profile.minimum_parallel_efficiency:
        failures.append("parallel_efficiency")
    if not observation.deterministic_digest_equal:
        failures.append("deterministic_digest_equal")
    if failures:
        raise ValidationCheckFailure(
            f"performance threshold failures {failures}", affected_record_ids=failures
        )
    return _passed(
        f"rows_per_second={observation.rows_per_second};peak_memory_bytes={observation.peak_memory_bytes};bytes_per_row={observation.bytes_per_row};parallel_efficiency={observation.parallel_efficiency}"
    )


def _passed(observed_value: str) -> CheckOutcome:
    return CheckOutcome(PASS, observed_value, (), "check executed and acceptance condition satisfied")


def _not_executed(message: str) -> CheckOutcome:
    return CheckOutcome(NOT_EXECUTED, None, (), message)


def _validate_outcome(check_id: str, outcome: CheckOutcome) -> None:
    if outcome.status not in {PASS, FAIL, NOT_APPLICABLE, NOT_EXECUTED}:
        raise JointValidationError(f"{check_id}: invalid outcome status {outcome.status!r}")
    if outcome.status == NOT_APPLICABLE and not outcome.message.startswith(JUSTIFICATION_PREFIX):
        raise JointValidationError(f"{check_id}: not_applicable lacks explicit justification code")
    if not outcome.message.strip():
        raise JointValidationError(f"{check_id}: outcome message is empty")


def _has_explicit_justification(row: Mapping[str, Any]) -> bool:
    return str(row.get("message", "")).startswith(JUSTIFICATION_PREFIX)


def _id_set(
    tables: Mapping[str, Sequence[Mapping[str, Any]]],
    table_name: str,
    field: str,
) -> set[str]:
    return {str(row[field]) for row in tables.get(table_name, ())}


def _record_identifier(table_name: str, row: Mapping[str, Any], index: int) -> str:
    fields = PRIMARY_KEYS.get(table_name, ())
    values = [str(row.get(field)) for field in fields if row.get(field) is not None]
    return "|".join(values) if values else f"{table_name}[{index}]"


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValidationCheckFailure(f"timestamp must be an ISO-8601 string, got {type(value).__name__}")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValidationCheckFailure(f"timestamp is timezone-naive: {value}")
    return parsed
