"""Deterministic full-replicate orchestration.

This layer does not fake later generator stages. It schedules every selected
scenario/replicate and invokes a supplied full-pipeline callable once per
``ResolvedRunPlan`` with deterministic seed records and ID helpers.
"""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from htgl_dataset_generator.anomalies import AnomalyBuild, build_anomalies, build_anomaly_baselines
from htgl_dataset_generator.arrivals import ArrivalBuild, build_arrivals
from htgl_dataset_generator.baselines import AnomalyBaselineBuild
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan, build_run_plan
from htgl_dataset_generator.dag import CausalDagBuild, build_causal_dag
from htgl_dataset_generator.evidence import (
    EvidenceObligationBuild,
    EvidenceReceiptBuild,
    build_evidence_obligations,
    build_evidence_receipts,
)
from htgl_dataset_generator.physical import PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.observers import ObserverBuild, build_observer_projections
from htgl_dataset_generator.metrics import (
    MetricConditionSeries,
    MetricsBuild,
    MetricsInput,
    PairedMetricComparison,
    PhysicalCalibrationReference,
    PrivacySourceReference,
    ReplicateMetricAggregate,
    aggregate_replicate_metrics,
    build_paired_crn_comparisons,
    build_run_metrics,
)
from htgl_dataset_generator.sampling import SamplingBuild, build_dependency_closed_sample
from htgl_dataset_generator.policy import PolicyOracleBuild, build_policy_oracle
from htgl_dataset_generator.schemas import load_contract
from htgl_dataset_generator.seeds import (
    CounterRng,
    DEFAULT_COMPONENT_STREAMS,
    canonical_records_digest,
    deterministic_uuid,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.workflows import WorkflowBuild, build_workflows
from htgl_dataset_generator.world import FederatedWorld, build_federated_world
from htgl_dataset_generator.validation import (
    ArtifactVerificationInput,
    PerformanceObservation,
    RegisteredValidationCheck,
    ReplicateExecutionEvidence,
    StagePerformanceObservation,
    ValidationBuild,
    ValidationInput,
    build_joint_validation,
    build_run_scenario_record,
)

from .execution import (
    CheckpointIntegrityError,
    DeterministicCheckpointStore,
    ParallelExecutionPolicy,
    resolve_execution_capacity,
)
from .profiling import StageProfiler


class PipelineCallable(Protocol):
    """Protocol for the later full stochastic generator pipeline."""

    def __call__(self, context: "ReplicateContext") -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class ReplicateContext:
    """Execution context for one full stochastic scenario/replicate."""

    resolved_config: ResolvedConfig
    run_plan: ResolvedRunPlan
    seed_stream_rows: tuple[Mapping[str, Any], ...]
    stage_profiler: StageProfiler | None = None

    @property
    def scenario_id(self) -> str:
        return self.run_plan.scenario_id

    @property
    def replicate_id(self) -> int:
        return self.run_plan.replicate_id

    def stream_row(self, component: str, partition: str = "global") -> Mapping[str, Any]:
        suffix = f"component={component}|partition={partition}"
        for row in self.seed_stream_rows:
            if row["stream_name"].endswith(suffix):
                return row
        raise KeyError(
            f"missing seed stream for scenario={self.scenario_id}, "
            f"replicate={self.replicate_id}, component={component}, partition={partition}"
        )

    def rng(self, component: str, partition: str = "global") -> CounterRng:
        return CounterRng(str(self.stream_row(component, partition)["seed_material_hex"]))

    def deterministic_id(
        self,
        component: str,
        entity_type: str,
        parts: Mapping[str, Any] | tuple[Any, ...] | list[Any] | str,
        partition: str = "global",
    ) -> str:
        namespace = str(self.stream_row(component, partition)["deterministic_id_namespace"])
        return deterministic_uuid(namespace, entity_type, parts)

    def profile_stage(
        self,
        stage_id: str,
        operation: str,
        function: Callable[[], Any],
        *,
        table_names: Iterable[str],
    ) -> Any:
        if self.stage_profiler is None:
            return function()
        expected = frozenset(table_names)

        def selected(value: Any) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
            tables = value.table_records()
            missing = sorted(expected - set(tables))
            if missing:
                raise RuntimeError(
                    f"stage {stage_id} measurement is missing table ownership {missing}"
                )
            return {name: tuple(tables[name]) for name in sorted(expected)}

        return self.stage_profiler.measure(
            stage_id,
            operation,
            function,
            table_records=selected,
        )


@dataclass(frozen=True)
class ReplicateResult:
    """Result of one full stochastic scenario/replicate execution."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    output: Mapping[str, Any]
    stage_performance: tuple[StagePerformanceObservation, ...] = ()


@dataclass(frozen=True)
class PipelineThroughDagBuild:
    """Validated artifacts for every implemented stochastic stage through the causal DAG."""

    world: FederatedWorld
    catalog: CatalogBuild
    physical: PhysicalRawBuild
    arrivals: ArrivalBuild
    workflows: WorkflowBuild
    causal_dag: CausalDagBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables: dict[str, tuple[dict[str, Any], ...]] = {}
        for stage_tables in (
            self.world.table_records(),
            self.catalog.table_records(),
            self.physical.table_records(),
            self.arrivals.table_records(),
            self.causal_dag.table_records(),
        ):
            overlap = sorted(set(tables) & set(stage_tables))
            if overlap:
                raise ValueError(f"duplicate authoritative table ownership {overlap}")
            tables.update(stage_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughDagResult:
    """One independently generated and validated replicate through the causal DAG stage."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughDagBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughPolicyBuild:
    """Validated artifacts for every implemented stage through policy truth."""

    through_dag: PipelineThroughDagBuild
    policy: PolicyOracleBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_dag.authoritative_table_records())
        policy_tables = self.policy.table_records()
        overlap = sorted(set(tables) & set(policy_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(policy_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughPolicyResult:
    """One independently generated and validated replicate through policy truth."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughPolicyBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughObligationsBuild:
    """Validated artifacts through policy-derived evidence obligations."""

    through_policy: PipelineThroughPolicyBuild
    evidence_obligations: EvidenceObligationBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_policy.authoritative_table_records())
        evidence_tables = self.evidence_obligations.table_records()
        overlap = sorted(set(tables) & set(evidence_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(evidence_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughObligationsResult:
    """One independently generated replicate through obligation compilation."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughObligationsBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughEvidenceBuild:
    """Validated artifacts through obligation-bound evidence receipt fixtures."""

    through_obligations: PipelineThroughObligationsBuild
    evidence_receipts: EvidenceReceiptBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_obligations.authoritative_table_records())
        receipt_tables = self.evidence_receipts.table_records()
        overlap = sorted(set(tables) & set(receipt_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(receipt_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughEvidenceResult:
    """One independently generated replicate through S10 evidence verification fixtures."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughEvidenceBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughAnomaliesBuild:
    """Validated artifacts through S08 minimal counterfactual anomaly truth."""

    through_evidence: PipelineThroughEvidenceBuild
    anomalies: AnomalyBuild
    anomaly_baselines: AnomalyBaselineBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_evidence.authoritative_table_records())
        anomaly_tables = self.anomalies.table_records()
        overlap = sorted(set(tables) & set(anomaly_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        if self.anomaly_baselines.table_records():
            raise ValueError("anomaly baselines must not own authoritative tables")
        tables.update(anomaly_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughAnomaliesResult:
    """One independently generated replicate through minimal anomalies and controls."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughAnomaliesBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughObserversBuild:
    """Validated artifacts through S11 protected and sanitized observer projections."""

    through_anomalies: PipelineThroughAnomaliesBuild
    observers: ObserverBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_anomalies.authoritative_table_records())
        observer_tables = self.observers.table_records()
        overlap = sorted(set(tables) & set(observer_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(observer_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughObserversResult:
    """One independently generated replicate through observer projection S11."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughObserversBuild
    table_digests: Mapping[str, str]


@dataclass(frozen=True)
class PipelineThroughSamplingBuild:
    """Validated artifacts through S12 dependency-closed probability sampling."""

    through_observers: PipelineThroughObserversBuild
    sampling: SamplingBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_observers.authoritative_table_records())
        sampling_tables = self.sampling.table_records()
        overlap = sorted(set(tables) & set(sampling_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(sampling_tables)
        existing_metrics = tuple(tables.get("run_metric", ()))
        combined_metrics = existing_metrics + self.sampling.run_metrics
        if len({str(row["metric_id"]) for row in combined_metrics}) != len(combined_metrics):
            raise ValueError("observer and sampling run_metric IDs collide")
        tables["run_metric"] = tuple(
            sorted(combined_metrics, key=lambda row: str(row["metric_id"]))
        )
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughSamplingResult:
    """One independently generated replicate through S12 sampling."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughSamplingBuild
    table_digests: Mapping[str, str]
    stage_performance: tuple[StagePerformanceObservation, ...] = ()


@dataclass(frozen=True)
class PipelineThroughValidationBuild:
    """Artifacts through S13 with explicit S00/S01 and validation rows."""

    through_sampling: PipelineThroughSamplingBuild
    run_scenario_records: tuple[dict[str, Any], ...]
    seed_stream_records: tuple[dict[str, Any], ...]
    validation: ValidationBuild

    def prevalidation_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_sampling.authoritative_table_records())
        for table_name, rows in (
            ("run_scenario", self.run_scenario_records),
            ("seed_stream", self.seed_stream_records),
        ):
            if table_name in tables:
                raise ValueError(f"duplicate authoritative table ownership {table_name}")
            tables[table_name] = rows
        return dict(sorted(tables.items()))

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.prevalidation_table_records())
        validation_tables = self.validation.table_records()
        overlap = sorted(set(tables) & set(validation_tables))
        if overlap:
            raise ValueError(f"duplicate authoritative table ownership {overlap}")
        tables.update(validation_tables)
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughValidationResult:
    """One complete replicate plus its finalized joint-validation ledger."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughValidationBuild
    table_digests: Mapping[str, str]
    stage_performance: tuple[StagePerformanceObservation, ...] = ()


@dataclass(frozen=True)
class PipelineThroughMetricsBuild:
    """One S00-S14 replicate with S14 owning the finalized run_metric ledger."""

    through_validation: PipelineThroughValidationBuild
    metrics: MetricsBuild

    def authoritative_table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        tables = dict(self.through_validation.authoritative_table_records())
        if "run_metric" not in tables:
            raise ValueError("S14 requires the provisional upstream run_metric table")
        tables["run_metric"] = self.metrics.run_metrics
        return dict(sorted(tables.items()))


@dataclass(frozen=True)
class PipelineThroughMetricsResult:
    """One complete replicate through S14 metrics."""

    run_plan: ResolvedRunPlan
    seed_stream_digest: str
    artifacts: PipelineThroughMetricsBuild
    table_digests: Mapping[str, str]
    stage_performance: tuple[StagePerformanceObservation, ...] = ()


@dataclass(frozen=True)
class PipelineMetricsRunGroupResult:
    """All S14 replicates plus cross-replicate and optional CRN comparison sidecars."""

    replicates: tuple[PipelineThroughMetricsResult, ...]
    aggregates: tuple[ReplicateMetricAggregate, ...]
    paired_comparisons: tuple[PairedMetricComparison, ...]


def schedule_run_plans(
    run_plans: Iterable[ResolvedRunPlan],
    *,
    worker_count: int = 1,
) -> tuple[ResolvedRunPlan, ...]:
    """Return the deterministic submission schedule for bounded workers."""

    if worker_count < 1:
        raise ValueError("worker_count must be positive")
    ordered = tuple(sorted(run_plans, key=lambda plan: (plan.scenario_id, plan.replicate_id)))
    buckets: list[list[ResolvedRunPlan]] = [[] for _ in range(worker_count)]
    for index, plan in enumerate(ordered):
        buckets[index % worker_count].append(plan)
    scheduled = [plan for bucket in buckets for plan in bucket]
    return tuple(scheduled)


def orchestrate_replicates(
    resolved_config: ResolvedConfig,
    pipeline: PipelineCallable | Callable[[ReplicateContext], Mapping[str, Any]],
    *,
    worker_count: int = 1,
    component_streams: Iterable[str] = DEFAULT_COMPONENT_STREAMS,
    partitions: Iterable[str] = ("global",),
    execution_policy: ParallelExecutionPolicy | None = None,
    checkpoint_dir: str | Path | None = None,
    checkpoint_namespace: str | None = None,
    resume: bool = False,
    profile_stages: bool = False,
) -> tuple[ReplicateResult, ...]:
    """Run the supplied full pipeline once per selected scenario/replicate.

    Results are returned in canonical scenario/replicate order even when bounded
    thread execution completes out of order. Checkpoints are trusted-local,
    versioned, and digest-verified; they are never publication artifacts.
    """

    if pipeline is None:
        raise ValueError("pipeline callable is required")

    policy = execution_policy or ParallelExecutionPolicy(worker_count=worker_count)
    if policy.worker_count != worker_count:
        raise ValueError(
            "execution_policy.worker_count must equal the explicit worker_count"
        )
    planned = build_run_plan(resolved_config)
    scheduled = schedule_run_plans(planned, worker_count=worker_count)
    capacity = resolve_execution_capacity(
        resolved_config,
        policy,
        task_count=len(scheduled),
    )
    if profile_stages and checkpoint_dir is not None:
        raise CheckpointIntegrityError(
            "stage profiling cannot reuse checkpoints because elapsed time and RSS must be "
            "measured from executed work"
        )
    if checkpoint_dir is not None and not checkpoint_namespace:
        raise CheckpointIntegrityError(
            "checkpoint_namespace is required when checkpoint_dir is supplied"
        )
    if checkpoint_dir is None and (checkpoint_namespace is not None or resume):
        raise CheckpointIntegrityError(
            "checkpoint namespace/resume requires an explicit checkpoint_dir"
        )
    store = (
        DeterministicCheckpointStore(
            checkpoint_dir,
            resolved=resolved_config,
            namespace=str(checkpoint_namespace),
        )
        if checkpoint_dir is not None
        else None
    )

    results: list[ReplicateResult] = []
    pending_plans: list[ResolvedRunPlan] = []
    for plan in scheduled:
        if store is not None and store.contains(plan):
            if not resume:
                raise CheckpointIntegrityError(
                    "checkpoint state already exists; pass resume=True to verify and reuse it"
                )
            restored = store.load(plan)
            if not isinstance(restored, ReplicateResult) or restored.run_plan != plan:
                raise CheckpointIntegrityError(
                    f"checkpoint result identity mismatch for {plan.scenario_id}:{plan.replicate_id}"
                )
            results.append(restored)
        else:
            pending_plans.append(plan)

    def execute(plan: ResolvedRunPlan) -> ReplicateResult:
        rows = seed_stream_records_for_plan(
            resolved_config,
            plan,
            component_streams=component_streams,
            partitions=partitions,
        )
        profiler = StageProfiler() if profile_stages else None
        context = ReplicateContext(
            resolved_config=resolved_config,
            run_plan=plan,
            seed_stream_rows=rows,
            stage_profiler=profiler,
        )
        output = dict(pipeline(context))
        result = ReplicateResult(
            run_plan=plan,
            seed_stream_digest=canonical_records_digest(rows),
            output=output,
            stage_performance=profiler.observations if profiler is not None else (),
        )
        if store is not None:
            store.save(plan, result)
        return result

    if capacity.effective_worker_count == 1:
        results.extend(execute(plan) for plan in pending_plans)
    elif pending_plans:
        with ThreadPoolExecutor(
            max_workers=capacity.effective_worker_count,
            thread_name_prefix="htgl-replicate",
        ) as executor:
            plan_iterator = iter(pending_plans)
            futures: dict[Future[ReplicateResult], ResolvedRunPlan] = {}

            def submit_one() -> bool:
                try:
                    plan = next(plan_iterator)
                except StopIteration:
                    return False
                futures[executor.submit(execute, plan)] = plan
                return True

            for _ in range(capacity.max_in_flight):
                if not submit_one():
                    break
            while futures:
                completed, _ = wait(tuple(futures), return_when=FIRST_COMPLETED)
                for future in sorted(
                    completed,
                    key=lambda item: (
                        futures[item].scenario_id,
                        futures[item].replicate_id,
                    ),
                ):
                    futures.pop(future)
                    results.append(future.result())
                    submit_one()

    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_dag(context: ReplicateContext) -> PipelineThroughDagBuild:
    """Execute and validate every currently implemented generator stage for one replicate."""

    contract = load_contract()
    scenario_ids = (context.scenario_id,)
    replicate_id = context.replicate_id
    world = context.profile_stage(
        "S02",
        "federated_world",
        lambda: build_federated_world(
            context.resolved_config,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=("actor", "actor_relationship", "prosumer_cohort", "network_area"),
    )
    catalog = context.profile_stage(
        "S03",
        "catalog_and_custody",
        lambda: build_catalog(
            context.resolved_config,
            world=world,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=("local_database", "data_object", "data_object_replica"),
    )
    physical = context.profile_stage(
        "S04",
        "physical_raw_backends",
        lambda: build_physical_raw(
            context.resolved_config,
            world=world,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=(
            "raw_meter_reading",
            "raw_der_telemetry",
            "raw_network_state",
            "raw_context_event",
        ),
    )
    arrivals = context.profile_stage(
        "S05",
        "hierarchical_arrivals",
        lambda: build_arrivals(
            context.resolved_config,
            world=world,
            catalog=catalog,
            physical=physical,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=("arrival",),
    )
    workflows = context.profile_stage(
        "S06",
        "workflow_compiler",
        lambda: build_workflows(
            context.resolved_config,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=("governance_event", "workflow_instance"),
    )
    causal_dag = context.profile_stage(
        "S07-dag",
        "causal_dag_and_closure",
        lambda: build_causal_dag(
            context.resolved_config,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            replicate_id=replicate_id,
            scenario_ids=scenario_ids,
            contract=contract,
        ),
        table_names=("event_edge",),
    )
    return PipelineThroughDagBuild(
        world=world,
        catalog=catalog,
        physical=physical,
        arrivals=arrivals,
        workflows=workflows,
        causal_dag=causal_dag,
    )


def orchestrate_pipeline_through_dag(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughDagResult, ...]:
    """Run all configured replicates through every implemented stage, or fail."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_dag(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} full replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughDagResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughDagBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} replicate={raw_result.run_plan.replicate_id}: "
                "pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughDagResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_policy(context: ReplicateContext) -> PipelineThroughPolicyBuild:
    """Execute and validate all implemented stages through independent policy truth."""

    through_dag = build_pipeline_through_dag(context)
    policy = context.profile_stage(
        "S07-policy",
        "independent_policy_oracle",
        lambda: build_policy_oracle(
            context.resolved_config,
            world=through_dag.world,
            catalog=through_dag.catalog,
            physical=through_dag.physical,
            arrivals=through_dag.arrivals,
            workflows=through_dag.workflows,
            causal_dag=through_dag.causal_dag,
            replicate_id=context.replicate_id,
            scenario_ids=(context.scenario_id,),
        ),
        table_names=("policy_rule", "policy_decision_truth"),
    )
    return PipelineThroughPolicyBuild(through_dag=through_dag, policy=policy)


def orchestrate_pipeline_through_policy(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughPolicyResult, ...]:
    """Run every configured replicate through policy truth, or fail."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_policy(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} policy replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughPolicyResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughPolicyBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} replicate={raw_result.run_plan.replicate_id}: "
                "policy pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughPolicyResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_obligations(context: ReplicateContext) -> PipelineThroughObligationsBuild:
    """Execute all implemented stages through deterministic evidence obligations."""

    through_policy = build_pipeline_through_policy(context)
    through_dag = through_policy.through_dag
    obligations = context.profile_stage(
        "S09",
        "policy_to_evidence_obligations",
        lambda: build_evidence_obligations(
            context.resolved_config,
            world=through_dag.world,
            catalog=through_dag.catalog,
            physical=through_dag.physical,
            arrivals=through_dag.arrivals,
            workflows=through_dag.workflows,
            causal_dag=through_dag.causal_dag,
            policy=through_policy.policy,
            replicate_id=context.replicate_id,
            scenario_ids=(context.scenario_id,),
        ),
        table_names=("evidence_obligation",),
    )
    return PipelineThroughObligationsBuild(
        through_policy=through_policy,
        evidence_obligations=obligations,
    )


def orchestrate_pipeline_through_obligations(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughObligationsResult, ...]:
    """Run every configured replicate through S09 obligation compilation, or fail."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_obligations(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} obligation replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughObligationsResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughObligationsBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} replicate={raw_result.run_plan.replicate_id}: "
                "obligation pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughObligationsResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_evidence(context: ReplicateContext) -> PipelineThroughEvidenceBuild:
    """Execute all implemented stages through independently verified S10 receipts."""

    through_obligations = build_pipeline_through_obligations(context)
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    receipts = context.profile_stage(
        "S10",
        "evidence_receipts_and_verification",
        lambda: build_evidence_receipts(
            context.resolved_config,
            world=through_dag.world,
            catalog=through_dag.catalog,
            physical=through_dag.physical,
            arrivals=through_dag.arrivals,
            workflows=through_dag.workflows,
            causal_dag=through_dag.causal_dag,
            policy=through_policy.policy,
            obligations=through_obligations.evidence_obligations,
            replicate_id=context.replicate_id,
            scenario_ids=(context.scenario_id,),
        ),
        table_names=("evidence_receipt",),
    )
    return PipelineThroughEvidenceBuild(
        through_obligations=through_obligations,
        evidence_receipts=receipts,
    )


def orchestrate_pipeline_through_evidence(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughEvidenceResult, ...]:
    """Run every configured replicate through S10 receipt generation and verification."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_evidence(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} evidence replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughEvidenceResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughEvidenceBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} replicate={raw_result.run_plan.replicate_id}: "
                "evidence pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughEvidenceResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_anomalies(context: ReplicateContext) -> PipelineThroughAnomaliesBuild:
    """Execute all implemented stages through S08 minimal counterfactual anomalies."""

    through_evidence = build_pipeline_through_evidence(context)
    through_obligations = through_evidence.through_obligations
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    common = {
        "world": through_dag.world,
        "catalog": through_dag.catalog,
        "physical": through_dag.physical,
        "workflows": through_dag.workflows,
        "causal_dag": through_dag.causal_dag,
        "policy": through_policy.policy,
        "obligations": through_obligations.evidence_obligations,
        "receipts": through_evidence.evidence_receipts,
        "replicate_id": context.replicate_id,
        "scenario_ids": (context.scenario_id,),
    }
    anomalies = context.profile_stage(
        "S08",
        "minimal_counterfactual_anomalies",
        lambda: build_anomalies(context.resolved_config, **common),
        table_names=("anomaly_instance",),
    )
    baselines = build_anomaly_baselines(context.resolved_config, **common)
    return PipelineThroughAnomaliesBuild(
        through_evidence=through_evidence,
        anomalies=anomalies,
        anomaly_baselines=baselines,
    )


def orchestrate_pipeline_through_anomalies(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughAnomaliesResult, ...]:
    """Run every configured replicate through S08 anomaly generation and baselines."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_anomalies(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} anomaly replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughAnomaliesResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughAnomaliesBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} replicate={raw_result.run_plan.replicate_id}: "
                "anomaly pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughAnomaliesResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_observers(context: ReplicateContext) -> PipelineThroughObserversBuild:
    """Execute one scenario/replicate through S11 observer projection and gates."""

    through_anomalies = build_pipeline_through_anomalies(context)
    through_evidence = through_anomalies.through_evidence
    through_obligations = through_evidence.through_obligations
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    observers = context.profile_stage(
        "S11",
        "observer_projection_and_omission_oracle",
        lambda: build_observer_projections(
            context.resolved_config,
            world=through_dag.world,
            catalog=through_dag.catalog,
            causal_dag=through_dag.causal_dag,
            policy=through_policy.policy,
            obligations=through_obligations.evidence_obligations,
            receipts=through_evidence.evidence_receipts,
            anomalies=through_anomalies.anomalies,
            replicate_id=context.replicate_id,
            scenario_ids=(context.scenario_id,),
        ),
        table_names=("observer_event",),
    )
    return PipelineThroughObserversBuild(
        through_anomalies=through_anomalies,
        observers=observers,
    )


def orchestrate_pipeline_through_observers(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
) -> tuple[PipelineThroughObserversResult, ...]:
    """Run every configured full replicate through the S11 observer stage."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_observers(context)},
        worker_count=worker_count,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} observer replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughObserversResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughObserversBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} "
                f"replicate={raw_result.run_plan.replicate_id}: "
                "observer pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughObserversResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_pipeline_through_sampling(context: ReplicateContext) -> PipelineThroughSamplingBuild:
    """Execute one complete scenario/replicate through S12 sampling gates."""

    through_observers = build_pipeline_through_observers(context)
    through_anomalies = through_observers.through_anomalies
    through_evidence = through_anomalies.through_evidence
    through_obligations = through_evidence.through_obligations
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    sampling = context.profile_stage(
        "S12",
        "dependency_closed_probability_sampling",
        lambda: build_dependency_closed_sample(
            context.resolved_config,
            world=through_dag.world,
            catalog=through_dag.catalog,
            causal_dag=through_dag.causal_dag,
            obligations=through_obligations.evidence_obligations,
            receipts=through_evidence.evidence_receipts,
            observers=through_observers.observers,
            replicate_id=context.replicate_id,
            scenario_ids=(context.scenario_id,),
        ),
        table_names=("sampling_design", "sample_membership"),
    )
    return PipelineThroughSamplingBuild(
        through_observers=through_observers,
        sampling=sampling,
    )


def orchestrate_pipeline_through_sampling(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
    execution_policy: ParallelExecutionPolicy | None = None,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    profile_stages: bool = False,
) -> tuple[PipelineThroughSamplingResult, ...]:
    """Run every configured full replicate through the S12 sampling stage."""

    raw_results = orchestrate_replicates(
        resolved_config,
        lambda context: {"artifacts": build_pipeline_through_sampling(context)},
        worker_count=worker_count,
        execution_policy=execution_policy,
        checkpoint_dir=checkpoint_dir,
        checkpoint_namespace="S12-sampling" if checkpoint_dir is not None else None,
        resume=resume,
        profile_stages=profile_stages,
    )
    expected_plans = build_run_plan(resolved_config)
    if len(raw_results) != len(expected_plans):
        raise RuntimeError(
            f"configured {len(expected_plans)} sampling replicates but executed {len(raw_results)}"
        )
    results: list[PipelineThroughSamplingResult] = []
    for raw_result in raw_results:
        artifacts = raw_result.output.get("artifacts")
        if not isinstance(artifacts, PipelineThroughSamplingBuild):
            raise RuntimeError(
                f"scenario={raw_result.run_plan.scenario_id} "
                f"replicate={raw_result.run_plan.replicate_id}: "
                "sampling pipeline did not return validated artifacts"
            )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughSamplingResult(
                run_plan=raw_result.run_plan,
                seed_stream_digest=raw_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
                stage_performance=raw_result.stage_performance,
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_validation_for_sampling_result(
    resolved_config: ResolvedConfig,
    sampling_result: PipelineThroughSamplingResult,
    *,
    replicate_evidence: Iterable[ReplicateExecutionEvidence],
    artifact_verification: ArtifactVerificationInput | None = None,
    reproducibility_reference_digests: Mapping[str, str] | None = None,
    performance_observation: PerformanceObservation | None = None,
    extensions: Iterable[RegisteredValidationCheck] = (),
) -> PipelineThroughValidationBuild:
    """Finalize S13 for one S12 result using run-group execution evidence."""

    contract = load_contract()
    run_plan = sampling_result.run_plan
    seed_rows = tuple(
        dict(row)
        for row in seed_stream_records_for_plan(
            resolved_config,
            run_plan,
            contract=contract,
        )
    )
    if canonical_records_digest(seed_rows) != sampling_result.seed_stream_digest:
        raise RuntimeError(
            f"scenario={run_plan.scenario_id} replicate={run_plan.replicate_id}: "
            "retained seed stream digest does not match regenerated S01 rows"
        )
    run_scenario_rows = (
        build_run_scenario_record(resolved_config, run_plan, contract=contract),
    )
    through_sampling = sampling_result.artifacts
    prevalidation_tables = dict(through_sampling.authoritative_table_records())
    prevalidation_tables["run_scenario"] = run_scenario_rows
    prevalidation_tables["seed_stream"] = seed_rows

    through_observers = through_sampling.through_observers
    through_anomalies = through_observers.through_anomalies
    through_evidence = through_anomalies.through_evidence
    through_obligations = through_evidence.through_obligations
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    validation = build_joint_validation(
        ValidationInput(
            resolved=resolved_config,
            run_plan=run_plan,
            run_scenario_rows=run_scenario_rows,
            seed_stream_rows=seed_rows,
            tables=dict(sorted(prevalidation_tables.items())),
            world=through_dag.world,
            catalog=through_dag.catalog,
            physical=through_dag.physical,
            arrivals=through_dag.arrivals,
            workflows=through_dag.workflows,
            causal_dag=through_dag.causal_dag,
            policy=through_policy.policy,
            obligations=through_obligations.evidence_obligations,
            receipts=through_evidence.evidence_receipts,
            anomalies=through_anomalies.anomalies,
            observers=through_observers.observers,
            sampling=through_sampling.sampling,
            replicate_evidence=tuple(replicate_evidence),
            artifact_verification=artifact_verification,
            reproducibility_reference_digests=reproducibility_reference_digests,
            performance_observation=performance_observation,
        ),
        extensions=extensions,
        contract=contract,
    )
    return PipelineThroughValidationBuild(
        through_sampling=through_sampling,
        run_scenario_records=run_scenario_rows,
        seed_stream_records=seed_rows,
        validation=validation,
    )


def orchestrate_pipeline_through_validation(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
    artifact_verification_by_run: Mapping[
        tuple[str, int], ArtifactVerificationInput
    ] | None = None,
    reproducibility_reference_by_run: Mapping[
        tuple[str, int], Mapping[str, str]
    ] | None = None,
    performance_observation_by_run: Mapping[
        tuple[str, int], PerformanceObservation
    ] | None = None,
    extensions: Iterable[RegisteredValidationCheck] = (),
    execution_policy: ParallelExecutionPolicy | None = None,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    profile_stages: bool = False,
) -> tuple[PipelineThroughValidationResult, ...]:
    """Run S00-S12 for every replicate, then execute the complete S13 registry."""

    sampling_results = orchestrate_pipeline_through_sampling(
        resolved_config,
        worker_count=worker_count,
        execution_policy=execution_policy,
        checkpoint_dir=checkpoint_dir,
        resume=resume,
        profile_stages=profile_stages,
    )
    replicate_evidence = tuple(
        ReplicateExecutionEvidence(
            scenario_id=result.run_plan.scenario_id,
            replicate_id=result.run_plan.replicate_id,
            seed_stream_digest=result.seed_stream_digest,
            retained_metric_count=len(
                result.artifacts.authoritative_table_records().get("run_metric", ())
            ),
        )
        for result in sampling_results
    )
    artifact_inputs = artifact_verification_by_run or {}
    reproducibility_inputs = reproducibility_reference_by_run or {}
    performance_inputs = performance_observation_by_run or {}
    extension_tuple = tuple(extensions)
    results: list[PipelineThroughValidationResult] = []
    for sampling_result in sampling_results:
        key = (
            sampling_result.run_plan.scenario_id,
            sampling_result.run_plan.replicate_id,
        )
        profiler = StageProfiler() if profile_stages else None

        def finalize_validation() -> PipelineThroughValidationBuild:
            return build_validation_for_sampling_result(
                resolved_config,
                sampling_result,
                replicate_evidence=replicate_evidence,
                artifact_verification=artifact_inputs.get(key),
                reproducibility_reference_digests=reproducibility_inputs.get(key),
                performance_observation=performance_inputs.get(key),
                extensions=extension_tuple,
            )

        artifacts = (
            profiler.measure(
                "S13",
                "fail_closed_joint_validation",
                finalize_validation,
                table_records=lambda value: {
                    "validation_issue": value.validation.validation_issues
                },
            )
            if profiler is not None
            else finalize_validation()
        )
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughValidationResult(
                run_plan=sampling_result.run_plan,
                seed_stream_digest=sampling_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
                stage_performance=(
                    sampling_result.stage_performance
                    + (profiler.observations if profiler is not None else ())
                ),
            )
        )
    return tuple(
        sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
    )


def build_metrics_for_validation_result(
    resolved_config: ResolvedConfig,
    validation_result: PipelineThroughValidationResult,
    *,
    physical_reference: PhysicalCalibrationReference | None = None,
    privacy_reference: PrivacySourceReference | None = None,
    artifact_verification: ArtifactVerificationInput | None = None,
    reproducibility_reference_digests: Mapping[str, str] | None = None,
    performance_observation: PerformanceObservation | None = None,
) -> PipelineThroughMetricsBuild:
    """Finalize the S14 metric ledger for one already validated S13 replicate."""

    through_validation = validation_result.artifacts
    through_sampling = through_validation.through_sampling
    through_observers = through_sampling.through_observers
    through_anomalies = through_observers.through_anomalies
    through_evidence = through_anomalies.through_evidence
    through_obligations = through_evidence.through_obligations
    through_policy = through_obligations.through_policy
    through_dag = through_policy.through_dag
    metrics = build_run_metrics(
        MetricsInput(
            resolved=resolved_config,
            run_plan=validation_result.run_plan,
            tables=through_validation.authoritative_table_records(),
            world=through_dag.world,
            catalog=through_dag.catalog,
            physical=through_dag.physical,
            arrivals=through_dag.arrivals,
            workflows=through_dag.workflows,
            causal_dag=through_dag.causal_dag,
            policy=through_policy.policy,
            obligations=through_obligations.evidence_obligations,
            receipts=through_evidence.evidence_receipts,
            anomalies=through_anomalies.anomalies,
            observers=through_observers.observers,
            sampling=through_sampling.sampling,
            validation=through_validation.validation,
            physical_reference=physical_reference,
            privacy_reference=privacy_reference,
            artifact_verification=artifact_verification,
            reproducibility_reference_digests=reproducibility_reference_digests,
            performance_observation=performance_observation,
        )
    )
    return PipelineThroughMetricsBuild(
        through_validation=through_validation,
        metrics=metrics,
    )


def orchestrate_pipeline_through_metrics(
    resolved_config: ResolvedConfig,
    *,
    worker_count: int = 1,
    physical_reference_by_run: Mapping[
        tuple[str, int], PhysicalCalibrationReference
    ] | None = None,
    privacy_reference_by_run: Mapping[
        tuple[str, int], PrivacySourceReference
    ] | None = None,
    artifact_verification_by_run: Mapping[
        tuple[str, int], ArtifactVerificationInput
    ] | None = None,
    reproducibility_reference_by_run: Mapping[
        tuple[str, int], Mapping[str, str]
    ] | None = None,
    performance_observation_by_run: Mapping[
        tuple[str, int], PerformanceObservation
    ] | None = None,
    extensions: Iterable[RegisteredValidationCheck] = (),
    paired_baseline: MetricConditionSeries | None = None,
    current_condition_id: str | None = None,
    current_condition_role: str = "treatment",
    current_common_random_group: str | None = None,
    execution_policy: ParallelExecutionPolicy | None = None,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    profile_stages: bool = False,
) -> PipelineMetricsRunGroupResult:
    """Run S00-S14, aggregate full replicates, and optionally compare a CRN baseline."""

    artifact_inputs = artifact_verification_by_run or {}
    reproducibility_inputs = reproducibility_reference_by_run or {}
    performance_inputs = performance_observation_by_run or {}
    validation_results = orchestrate_pipeline_through_validation(
        resolved_config,
        worker_count=worker_count,
        artifact_verification_by_run=artifact_inputs,
        reproducibility_reference_by_run=reproducibility_inputs,
        performance_observation_by_run=performance_inputs,
        extensions=extensions,
        execution_policy=execution_policy,
        checkpoint_dir=checkpoint_dir,
        resume=resume,
        profile_stages=profile_stages,
    )
    physical_inputs = physical_reference_by_run or {}
    privacy_inputs = privacy_reference_by_run or {}
    results: list[PipelineThroughMetricsResult] = []
    metric_builds: list[MetricsBuild] = []
    for validation_result in validation_results:
        key = (validation_result.run_plan.scenario_id, validation_result.run_plan.replicate_id)
        profiler = StageProfiler() if profile_stages else None

        def finalize_metrics() -> PipelineThroughMetricsBuild:
            return build_metrics_for_validation_result(
                resolved_config,
                validation_result,
                physical_reference=physical_inputs.get(key),
                privacy_reference=privacy_inputs.get(key),
                artifact_verification=artifact_inputs.get(key),
                reproducibility_reference_digests=reproducibility_inputs.get(key),
                performance_observation=performance_inputs.get(key),
            )

        artifacts = (
            profiler.measure(
                "S14",
                "metrics_and_uncertainty",
                finalize_metrics,
                table_records=lambda value: {"run_metric": value.metrics.run_metrics},
            )
            if profiler is not None
            else finalize_metrics()
        )
        metric_builds.append(artifacts.metrics)
        table_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in artifacts.authoritative_table_records().items()
        }
        results.append(
            PipelineThroughMetricsResult(
                run_plan=validation_result.run_plan,
                seed_stream_digest=validation_result.seed_stream_digest,
                artifacts=artifacts,
                table_digests=dict(sorted(table_digests.items())),
                stage_performance=(
                    validation_result.stage_performance
                    + (profiler.observations if profiler is not None else ())
                ),
            )
        )
    aggregates = aggregate_replicate_metrics(metric_builds, resolved_config)
    comparisons: tuple[PairedMetricComparison, ...] = ()
    if paired_baseline is not None:
        if not current_condition_id or not current_common_random_group:
            raise ValueError(
                "paired S14 comparison requires current_condition_id and current_common_random_group"
            )
        scenario_ids = {result.run_plan.scenario_id for result in results}
        if len(scenario_ids) != 1:
            raise ValueError("paired S14 comparisons require one scenario per condition")
        current = MetricConditionSeries(
            condition_id=current_condition_id,
            condition_role=current_condition_role,
            common_random_group=current_common_random_group,
            metrics=tuple(
                row for build in metric_builds for row in build.run_metrics
            ),
            provenance=tuple(
                item for build in metric_builds for item in build.provenance
            ),
        )
        comparisons = build_paired_crn_comparisons(
            paired_baseline,
            (current,),
            resolved_config,
        )
    return PipelineMetricsRunGroupResult(
        replicates=tuple(
            sorted(results, key=lambda result: (result.run_plan.scenario_id, result.run_plan.replicate_id))
        ),
        aggregates=aggregates,
        paired_comparisons=comparisons,
    )
