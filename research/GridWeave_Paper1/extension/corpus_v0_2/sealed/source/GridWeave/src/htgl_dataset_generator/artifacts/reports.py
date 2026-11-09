"""Checksum-bound S15 publication cards, quality reports, and claim matrix."""

from __future__ import annotations

from collections import Counter
import csv
from dataclasses import dataclass
from html import escape
import io
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.config import (
    CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE,
)

from .canonical import atomic_write_bytes, canonical_json_bytes, domain_sha256, sha256_hex
from .models import (
    ArtifactIntegrityError,
    DownstreamReplayObservation,
    StoredArtifact,
)


GENERATOR_BOUNDARY = (
    "benchmark_artifacts_only_no_htgl_consensus_ledger_real_erasure_legal_enforcement_or_utility_deployment"
)
CLAIM_MATRIX_COLUMNS = (
    "claim_id",
    "claim_text",
    "evidence_class",
    "scenario/replicates",
    "artifact_ids",
    "metric/estimator",
    "baseline/ablation",
    "assumptions",
    "limitations",
    "validation_gate",
    "claim_status",
)
PUBLIC_REPORT_FORBIDDEN_FIELDS = (
    "anomaly_instance_id",
    "protected_pair_id",
    "source_event_id",
    "first_order_inclusion_probability",
    "is_violation",
)
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_WORDING = (
    (
        "represented_population_as_operational_capacity",
        re.compile(
            r"\b(?:HTGL|generator)\b[^.\n]{0,80}\b(?:handled|processed|executed)\b"
            r"[^.\n]{0,40}\b450\s*(?:million|m)\s*(?:users|people)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unobserved_transaction_execution",
        re.compile(
            r"\b900\s*(?:million|m)\s*(?:transactions|operations)\b[^.\n]{0,40}\bexecuted\b",
            re.IGNORECASE,
        ),
    ),
    (
        "physical_erasure_proof",
        re.compile(r"\bproof\s+of\s+(?:physical\s+)?erasure\b", re.IGNORECASE),
    ),
    (
        "unscoped_legal_compliance",
        re.compile(r"\bGDPR[- ]compliant\b", re.IGNORECASE),
    ),
    (
        "unsupported_novelty_priority",
        re.compile(
            r"\b(?:first|novel)\s+(?:algorithm|method|approach|system|framework)\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class ClaimMatrixRow:
    """One Appendix D claim-to-artifact traceability row."""

    claim_id: str
    claim_text: str
    evidence_class: str
    scenario_replicates: str
    artifact_ids: str
    metric_estimator: str
    baseline_ablation: str
    assumptions: str
    limitations: str
    validation_gate: str
    claim_status: str

    def csv_row(self) -> tuple[str, ...]:
        return (
            self.claim_id,
            self.claim_text,
            self.evidence_class,
            self.scenario_replicates,
            self.artifact_ids,
            self.metric_estimator,
            self.baseline_ablation,
            self.assumptions,
            self.limitations,
            self.validation_gate,
            self.claim_status,
        )


@dataclass(frozen=True)
class PublicationReportBuild:
    """Deterministic public reports and their source-inventory binding."""

    paths: tuple[Path, ...]
    claim_rows: tuple[ClaimMatrixRow, ...]
    source_inventory_digest: str
    cited_artifact_ids: tuple[str, ...]


def build_claim_matrix(
    resolved: Any,
    tables_by_run: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    *,
    downstream_replay_by_run: Mapping[
        tuple[str, int], DownstreamReplayObservation
    ] | None = None,
) -> dict[str, Any]:
    """Build the compact release-claim guard consumed by the S15 gate.

    This guard is deliberately separate from the Appendix D CSV.  It carries
    machine-enforced N/n/q and claim-boundary flags while the CSV contains exact
    manuscript-ready claim rows with artifact checksums.
    """

    event_rows = sum(
        len(tables.get("governance_event", ())) for tables in tables_by_run.values()
    )
    executed_operations = validate_downstream_replay_evidence(
        resolved,
        tables_by_run.keys(),
        downstream_replay_by_run,
    )
    return {
        "represented_population": resolved.claim_scale.represented_population,
        "materialized_rows": event_rows,
        "materialized_row_target": resolved.claim_scale.materialized_row_target,
        "executed_operations": executed_operations,
        "executed_operation_target": resolved.claim_scale.executed_operation_target,
        "generator_boundary": GENERATOR_BOUNDARY,
        "legal_compliance_claim": False,
        "real_deletion_claim": False,
        "cryptographic_proof_scope": "configured synthetic evidence fixtures and verification truth only",
        "operational_execution_claim": executed_operations is not None,
        "represented_population_is_materialized": False,
        "represented_population_is_executed": False,
        "policy_output_scope": "experimental policy-profile truth, not legal advice or a compliance finding",
        "erasure_output_scope": "model-level feasibility under declared evidence assumptions, not physical deletion",
    }


def validate_downstream_replay_evidence(
    resolved: Any,
    expected_keys: Iterable[tuple[str, int]],
    observations: Mapping[tuple[str, int], DownstreamReplayObservation] | None,
) -> int | None:
    """Validate measured downstream replay evidence and return observed ``q``."""

    if not observations:
        return None
    expected = set(expected_keys)
    actual = set(observations)
    if actual != expected:
        raise ArtifactIntegrityError(
            "downstream replay evidence must cover every released run exactly "
            f"missing={sorted(expected-actual)} extra={sorted(actual-expected)}"
        )
    if not resolved.claim_scale.operational_claim_allowed:
        raise ArtifactIntegrityError(
            "downstream replay evidence was supplied but operational_claim_allowed is false"
        )
    if resolved.claim_scale.executed_operation_target is None:
        raise ArtifactIntegrityError(
            "downstream replay evidence requires a pinned executed_operation_target"
        )
    total = 0
    for key, item in sorted(observations.items()):
        if key != (item.scenario_id, item.replicate_id):
            raise ArtifactIntegrityError(
                f"downstream replay key={key} disagrees with observation identity"
            )
        if item.run_id != resolved.run.run_id:
            raise ArtifactIntegrityError(
                f"downstream replay key={key} has run_id={item.run_id!r}, expected {resolved.run.run_id!r}"
            )
        _require_nonempty_replay_labels(item, key)
        if item.executed_operation_count <= 0:
            raise ArtifactIntegrityError(
                f"downstream replay key={key} must report a positive executed operation count"
            )
        for label, digest in (
            ("workload_sha256", item.workload_sha256),
            ("result_sha256", item.result_sha256),
        ):
            if _DIGEST_PATTERN.fullmatch(digest) is None:
                raise ArtifactIntegrityError(
                    f"downstream replay key={key} {label} must be a lowercase SHA-256 digest"
                )
        numeric = {
            "throughput_operations_per_second": item.throughput_operations_per_second,
            "p50_latency_milliseconds": item.p50_latency_milliseconds,
            "p95_latency_milliseconds": item.p95_latency_milliseconds,
        }
        for label, value in numeric.items():
            if not math.isfinite(value) or value < 0.0:
                raise ArtifactIntegrityError(
                    f"downstream replay key={key} {label} must be finite and non-negative"
                )
        if item.throughput_operations_per_second <= 0.0:
            raise ArtifactIntegrityError(
                f"downstream replay key={key} throughput must be positive"
            )
        if item.p95_latency_milliseconds < item.p50_latency_milliseconds:
            raise ArtifactIntegrityError(
                f"downstream replay key={key} p95 latency cannot be below p50 latency"
            )
        if item.peak_resident_memory_bytes <= 0:
            raise ArtifactIntegrityError(
                f"downstream replay key={key} peak memory must be positive"
            )
        total += item.executed_operation_count
    return total


def write_reports(
    root: Path,
    *,
    artifact_root: Path,
    resolved: Any,
    claim_matrix: Mapping[str, Any],
    source_artifacts: Sequence[StoredArtifact],
    source_manifest_rows: Sequence[Mapping[str, Any]],
    downstream_replay_by_run: Mapping[
        tuple[str, int], DownstreamReplayObservation
    ] | None = None,
) -> PublicationReportBuild:
    """Compile public reports from hash-verified staged artifact bytes only."""

    artifacts = tuple(source_artifacts)
    manifest_rows = tuple(source_manifest_rows)
    artifact_index = _verify_source_inventory(artifact_root, artifacts, manifest_rows)
    config = _read_json_artifact(artifact_root, artifact_index, "config/config_resolved.json")
    if config != resolved.as_dict():
        raise ArtifactIntegrityError(
            "immutable config/config_resolved.json disagrees with the resolved run plan"
        )
    if config.get("config_sha256") != resolved.config_sha256:
        raise ArtifactIntegrityError("report source config SHA-256 is not the resolved digest")
    _validate_claim_contract_against_artifacts(
        config,
        claim_matrix,
        artifacts,
        downstream_replay_by_run,
    )

    validation_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "validation/validation_issue.parquet"
    )
    metric_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "metrics/run_metric.parquet"
    )
    provenance_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "metrics/observation_provenance.parquet"
    )
    aggregate_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "metrics/replicate_summary.parquet"
    )
    execution_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "metrics/metric_execution.parquet"
    )
    paired_rows = _read_parquet_artifact(
        artifact_root, artifact_index, "metrics/baselines.parquet"
    )
    baseline_rows = _read_optional_parquet_artifact(
        artifact_root, artifact_index, "metrics/baseline_comparisons.parquet"
    )
    baseline_condition_rows = _read_optional_parquet_artifact(
        artifact_root, artifact_index, "metrics/baseline_conditions.parquet"
    )
    validation_metadata = _read_json_artifact(
        artifact_root, artifact_index, "validation/validation_metadata.json"
    )
    metrics_metadata = _read_json_artifact(
        artifact_root, artifact_index, "metrics/metrics_metadata.json"
    )
    reproducibility = _read_json_artifact(
        artifact_root, artifact_index, "provenance/reproducibility.json"
    )
    _validate_report_inputs(
        config,
        claim_matrix,
        validation_rows,
        metric_rows,
        provenance_rows,
        execution_rows,
        validation_metadata,
        metrics_metadata,
    )

    inventory_digest = domain_sha256(
        "S15-publication-report-source-inventory-v1",
        [(item.relative_path, item.sha256) for item in artifacts],
    )
    claim_rows = _build_claim_rows(
        config=config,
        claim_contract=claim_matrix,
        artifact_index=artifact_index,
        validation_rows=validation_rows,
        metric_rows=metric_rows,
        provenance_rows=provenance_rows,
        aggregate_rows=aggregate_rows,
        paired_rows=paired_rows,
        baseline_rows=baseline_rows,
        baseline_condition_rows=baseline_condition_rows,
        reproducibility=reproducibility,
        downstream_replay_by_run=downstream_replay_by_run,
    )
    report_root = root / "reports"
    paths: list[Path] = []
    paths.append(_write_claim_matrix(report_root, claim_rows))
    paths.append(
        _write_metric_trace(
            report_root,
            metric_rows,
            provenance_rows,
            artifact_index,
            _validation_gate(config, validation_rows),
        )
    )
    paths.append(
        _write_data_card(
            report_root,
            config,
            claim_matrix,
            artifacts,
            validation_rows,
            metric_rows,
            aggregate_rows,
            baseline_condition_rows,
            reproducibility,
            inventory_digest,
            claim_rows,
        )
    )
    paths.append(
        _write_model_card(
            report_root,
            config,
            metrics_metadata,
            validation_metadata,
            claim_rows,
            inventory_digest,
        )
    )
    paths.extend(
        _write_quality_reports(
            report_root,
            config,
            validation_rows,
            metric_rows,
            aggregate_rows,
            paired_rows,
            baseline_rows,
            reproducibility,
            inventory_digest,
            claim_rows,
            artifact_index,
        )
    )
    paths.extend(_write_baseline_reports(report_root, baseline_rows))
    evidence_path = report_root / "report_evidence.json"
    atomic_write_bytes(
        evidence_path,
        canonical_json_bytes(
            {
                "format": "htgl.publication-report-evidence.v1",
                "run_id": config["run"]["run_id"],
                "config_sha256": config["config_sha256"],
                "source_inventory_digest": inventory_digest,
                "source_artifacts": [
                    {
                        "artifact_id": artifact_index[item.relative_path]["artifact_id"],
                        "relative_path": item.relative_path,
                        "sha256": item.sha256,
                    }
                    for item in artifacts
                ],
                "claim_ids": [row.claim_id for row in claim_rows],
                "claim_status_counts": dict(
                    sorted(Counter(row.claim_status for row in claim_rows).items())
                ),
                "reports_are_manifest_precursors": True,
                "final_manifest_closure_required": True,
            }
        ),
    )
    paths.append(evidence_path)

    for path in paths:
        _validate_public_report_content(path)
    cited = tuple(
        sorted(
            {
                token.split("|", 1)[0]
                for row in claim_rows
                for token in row.artifact_ids.split(";")
                if token and not token.startswith("external:")
            }
        )
    )
    return PublicationReportBuild(
        paths=tuple(sorted(paths)),
        claim_rows=claim_rows,
        source_inventory_digest=inventory_digest,
        cited_artifact_ids=cited,
    )


def validate_publication_wording(text: str) -> None:
    """Reject report wording that exceeds the generator's evidence boundary."""

    for rule_id, pattern in _FORBIDDEN_WORDING:
        match = pattern.search(text)
        if match:
            raise ArtifactIntegrityError(
                f"publication wording violates {rule_id}: {match.group(0)!r}"
            )


def validate_claim_trace_closure(
    report: PublicationReportBuild,
    final_manifest_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Require every internally cited claim artifact to survive final inventory."""

    final_ids = {str(row["artifact_id"]) for row in final_manifest_rows}
    missing = sorted(set(report.cited_artifact_ids) - final_ids)
    if missing:
        raise ArtifactIntegrityError(
            f"publication claim matrix cites artifacts absent from final manifest: {missing}"
        )
    duplicate_claim_ids = [
        claim_id
        for claim_id, count in Counter(row.claim_id for row in report.claim_rows).items()
        if count != 1
    ]
    if duplicate_claim_ids:
        raise ArtifactIntegrityError(
            f"publication claim matrix has duplicate claim IDs {sorted(duplicate_claim_ids)}"
        )


def _build_claim_rows(
    *,
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    artifact_index: Mapping[str, Mapping[str, Any]],
    validation_rows: Sequence[Mapping[str, Any]],
    metric_rows: Sequence[Mapping[str, Any]],
    provenance_rows: Sequence[Mapping[str, Any]],
    aggregate_rows: Sequence[Mapping[str, Any]],
    paired_rows: Sequence[Mapping[str, Any]],
    baseline_rows: Sequence[Mapping[str, Any]],
    baseline_condition_rows: Sequence[Mapping[str, Any]],
    reproducibility: Mapping[str, Any],
    downstream_replay_by_run: Mapping[
        tuple[str, int], DownstreamReplayObservation
    ] | None,
) -> tuple[ClaimMatrixRow, ...]:
    provenance = {str(row["metric_id"]): row for row in provenance_rows}
    gate = _validation_gate(config, validation_rows)
    metric_artifacts = _artifact_tokens(
        artifact_index,
        "metrics/run_metric.parquet",
        "metrics/observation_provenance.parquet",
        "validation/validation_issue.parquet",
    )
    rows: list[ClaimMatrixRow] = []
    rows.append(
        _scale_contract_claim(config, claim_contract, artifact_index, gate)
    )
    rows.append(_validation_claim(config, validation_rows, artifact_index, gate))
    rows.append(_reproducibility_claim(config, reproducibility, artifact_index, gate))

    for metric in sorted(metric_rows, key=lambda item: str(item["metric_id"])):
        item = provenance[str(metric["metric_id"])]
        status = "supported" if bool(item["publication_eligible"]) else "diagnostic_only"
        interval = _interval_text(metric)
        claim_text = (
            f"For scenario {metric['scenario_id']} replicate {metric['replicate_id']}, "
            f"{metric['metric_name']} was {_number(metric['value'])} {metric['unit']}"
            f"{interval} using {metric['estimator']} with {metric['weighting']} weighting."
        )
        if status != "supported":
            claim_text = "Diagnostic only; not publication-eligible. " + claim_text
        rows.append(
            ClaimMatrixRow(
                claim_id=_claim_id("METRIC", metric["metric_id"]),
                claim_text=claim_text,
                evidence_class=_metric_evidence_class(metric, config),
                scenario_replicates=(
                    f"{metric['scenario_id']} / replicate {metric['replicate_id']}"
                ),
                artifact_ids=metric_artifacts,
                metric_estimator=(
                    f"{metric['metric_name']} / {item['definition_id']} / "
                    f"{metric['estimator']} / registry_sha256={item['registry_sha256']}"
                ),
                baseline_ablation=str(metric.get("baseline_id") or "none"),
                assumptions=_metric_assumptions(item, config),
                limitations=_metric_limitations(item, status),
                validation_gate=gate,
                claim_status=status,
            )
        )

    aggregate_artifacts = _artifact_tokens(
        artifact_index,
        "metrics/replicate_summary.parquet",
        "metrics/observation_provenance.parquet",
        "validation/validation_issue.parquet",
    )
    registry_id = str(next(iter(provenance.values()))["registry_id"])
    registry_sha = str(next(iter(provenance.values()))["registry_sha256"])
    for item in sorted(aggregate_rows, key=lambda row: str(row["aggregate_id"])):
        status = "supported" if item["uncertainty_status"] != "insufficient_replicates" else "diagnostic_only"
        uncertainty = _aggregate_uncertainty_text(item)
        rows.append(
            ClaimMatrixRow(
                claim_id=_claim_id("AGGREGATE", item["aggregate_id"]),
                claim_text=(
                    ("" if status == "supported" else "Diagnostic only; independent-replicate uncertainty is unavailable. ")
                    + f"Across replicates {_join_ints(item['replicate_ids'])} for scenario {item['scenario_id']}, "
                    + f"mean {item['metric_key']} was {_number(item['mean_value'])} {item['unit']}{uncertainty}."
                ),
                evidence_class=_aggregate_evidence_class(item, config),
                scenario_replicates=(
                    f"{item['scenario_id']} / replicates {_join_ints(item['replicate_ids'])}"
                ),
                artifact_ids=aggregate_artifacts,
                metric_estimator=(
                    f"{item['metric_key']} / {registry_id}:{item['metric_key']} / "
                    f"{item['estimator']} / registry_sha256={registry_sha}"
                ),
                baseline_ablation=str(item.get("baseline_id") or "none"),
                assumptions=(
                    f"independent full-pipeline replicate set; scope_id={item['scope_id']}; "
                    f"uncertainty_method={item['uncertainty_method']}"
                ),
                limitations=(
                    str(item["uncertainty_reason"])
                    + "; generated benchmark result only; no operational HTGL capacity inference"
                ),
                validation_gate=gate,
                claim_status=status,
            )
        )

    rows.extend(
        _paired_claim_rows(paired_rows, artifact_index, config, gate, "metrics/baselines.parquet")
    )
    rows.extend(
        _paired_claim_rows(
            baseline_rows,
            artifact_index,
            config,
            gate,
            "metrics/baseline_comparisons.parquet",
        )
    )
    rows.extend(
        _maturity_claims(
            config,
            claim_contract,
            artifact_index,
            validation_rows,
            metric_rows,
            provenance_rows,
            aggregate_rows,
            baseline_condition_rows,
            reproducibility,
            downstream_replay_by_run,
            gate,
        )
    )
    ordered = tuple(sorted(rows, key=lambda row: row.claim_id))
    if len({row.claim_id for row in ordered}) != len(ordered):
        raise ArtifactIntegrityError("claim compiler produced duplicate stable claim IDs")
    for row in ordered:
        validate_publication_wording(row.claim_text)
        _reject_public_field_leakage(row.csv_row())
        if not row.artifact_ids:
            raise ArtifactIntegrityError(f"claim {row.claim_id} has no artifact checksum evidence")
        if not row.validation_gate:
            raise ArtifactIntegrityError(f"claim {row.claim_id} has no validation gate")
    return ordered


def _maturity_claims(
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    artifact_index: Mapping[str, Mapping[str, Any]],
    validation_rows: Sequence[Mapping[str, Any]],
    metric_rows: Sequence[Mapping[str, Any]],
    provenance_rows: Sequence[Mapping[str, Any]],
    aggregate_rows: Sequence[Mapping[str, Any]],
    baseline_condition_rows: Sequence[Mapping[str, Any]],
    reproducibility: Mapping[str, Any],
    downstream_replay_by_run: Mapping[
        tuple[str, int], DownstreamReplayObservation
    ] | None,
    gate: str,
) -> tuple[ClaimMatrixRow, ...]:
    scale = config["claim_scale"]
    run = config["run"]
    published_metric_names = {
        str(row["metric_key"])
        for row in provenance_rows
        if bool(row["publication_eligible"])
    }
    common_artifacts = _artifact_tokens(
        artifact_index,
        "config/config_resolved.json",
        "metrics/run_metric.parquet",
        "metrics/observation_provenance.parquet",
        "validation/validation_issue.parquet",
        "provenance/reproducibility.json",
    )

    snapshot_supported = (
        int(claim_contract["represented_population"]) == 450_000_000
        and int(claim_contract["materialized_rows"]) == 100_000
    )
    snapshot_text = (
        "The release materializes a 100,000-row weighted governance-event artifact under a "
        "configuration representing 450 million people."
        if snapshot_supported
        else "This release does not establish the 100,000-row under 450-million represented-population maturity statement; its recorded N and n differ."
    )

    statistical_required = {
        "count_mean_ratio",
        "time_rescaling_ks",
        "transition_conformance_rate",
    }
    statistical_supported = (
        int(run["replicate_count"]) >= 2
        and statistical_required <= published_metric_names
        and bool(reproducibility.get("semantic_match"))
        and bool(reproducibility.get("byte_match"))
    )
    statistical_text = (
        "The generator reproduced the declared point-process and workflow properties within "
        f"the reported diagnostics across {run['replicate_count']} independent full-pipeline repetitions."
        if statistical_supported
        else "This release does not establish repeated point-process and workflow reproduction because independent repetition, required diagnostics, or reproducibility evidence is incomplete."
    )

    bias_rows = [row for row in metric_rows if row["metric_name"] == "relative_bias_known_total"]
    coverage_rows = [row for row in metric_rows if row["metric_name"] == "ci_coverage"]
    scale_supported = (
        int(scale["represented_population"]) == 450_000_000
        and bool(scale["scale_claim_allowed"])
        and bool(scale["estimator_eligible"])
        and bool(bias_rows)
        and bool(coverage_rows)
        and all(abs(float(row["value"])) <= float(config["sampling"]["maximum_absolute_relative_bias"]) for row in bias_rows)
        and all(float(row["value"]) >= float(config["sampling"]["minimum_ci_coverage"]) for row in coverage_rows)
    )
    scale_text = (
        "Under the configured probability sampling design, design-based estimates recovered "
        "known totals for the synthetic population represented as N=450,000,000 within the declared bias and confidence-interval coverage requirements."
        if scale_supported
        else "This release does not establish known-total recovery at N=450,000,000 because the represented-scale, estimator, bias, or confidence-interval coverage gate is not satisfied."
    )

    replay_supported = bool(downstream_replay_by_run)
    if replay_supported:
        q = int(claim_contract["executed_operations"])
        replay_text = (
            f"The separately identified downstream implementations processed q={q} replay operations under the hardware and software profiles recorded in this claim matrix."
        )
        replay_artifacts = ";".join(
            sorted(
                {
                    f"external:workload|sha256={item.workload_sha256}"
                    for item in downstream_replay_by_run.values()
                }
                | {
                    f"external:result|sha256={item.result_sha256}"
                    for item in downstream_replay_by_run.values()
                }
            )
        )
    else:
        replay_text = (
            "No downstream replay execution claim is supported for this release; q is recorded as not executed."
        )
        replay_artifacts = _artifact_tokens(artifact_index, "config/config_resolved.json")

    basis = (
        str(config["policy"]["profile_id"])
        + "; source_labels="
        + _source_label_summary(config)
    )
    return (
        ClaimMatrixRow(
            "C-MATURITY-SNAPSHOT-01",
            snapshot_text,
            "represented-scale",
            f"{run['selected_scenario_ids']} / replicates 0-{int(run['replicate_count'])-1}",
            common_artifacts,
            "materialized governance-event row census / none",
            "none",
            basis,
            "Represented population is exposure, not materialized users or executed operations.",
            gate,
            "supported" if snapshot_supported else "not_supported",
        ),
        ClaimMatrixRow(
            "C-MATURITY-STATISTICAL-01",
            statistical_text,
            "simulation",
            f"{run['selected_scenario_ids']} / replicates 0-{int(run['replicate_count'])-1}",
            common_artifacts,
            "count_mean_ratio; time_rescaling_ks; transition_conformance_rate / registry-defined estimators",
            "executed_baseline_conditions=" + str(len(baseline_condition_rows)),
            basis,
            "Diagnostics are scoped to the declared controlled procedural synthetic scenarios.",
            gate,
            "supported" if statistical_supported else "not_supported",
        ),
        ClaimMatrixRow(
            "C-MATURITY-SCALE-01",
            scale_text,
            "represented-scale",
            f"{run['selected_scenario_ids']} / replicates 0-{int(run['replicate_count'])-1}",
            common_artifacts,
            "relative_bias_known_total and ci_coverage / configured design-based estimator",
            "sampling controls remain claim-ineligible unless inclusion probabilities are valid",
            basis,
            "This is synthetic known-total recovery, not operational scalability.",
            gate,
            "supported" if scale_supported else "not_supported",
        ),
        ClaimMatrixRow(
            "C-MATURITY-REPLAY-01",
            replay_text,
            "deployment-measured",
            f"{run['selected_scenario_ids']} / downstream replay observations",
            replay_artifacts,
            "executed operation count, throughput, latency, and peak memory / external measurement",
            "none",
            "separately identified implementation, version, software profile, and hardware profile",
            "Replay evidence is bounded to q, the stated implementation, hardware, software, and workload checksums.",
            gate + "; REP-EXEC-001",
            "supported" if replay_supported else "not_supported",
        ),
    )


def _scale_contract_claim(
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    artifact_index: Mapping[str, Mapping[str, Any]],
    gate: str,
) -> ClaimMatrixRow:
    q = claim_contract["executed_operations"]
    q_text = "not executed" if q is None else str(q)
    return ClaimMatrixRow(
        claim_id="C-SCALE-CONTRACT-01",
        claim_text=(
            f"Release {config['run']['run_id']} represents N={claim_contract['represented_population']}, "
            f"materializes n={claim_contract['materialized_rows']} governance-event rows, and records q={q_text}."
        ),
        evidence_class="represented-scale",
        scenario_replicates=(
            f"{config['run']['selected_scenario_ids']} / replicates 0-{int(config['run']['replicate_count'])-1}"
        ),
        artifact_ids=_artifact_tokens(
            artifact_index,
            "config/config_resolved.json",
            *_paths_with_prefix(artifact_index, "canonical/events/"),
        ),
        metric_estimator="N configured represented exposure; n manifest row census; q measured downstream replay only",
        baseline_ablation="none",
        assumptions=str(config["claim_scale"]["aggregation_semantics"]),
        limitations="N, n, and q are distinct; no operational capacity follows from represented exposure.",
        validation_gate=gate,
        claim_status="supported",
    )


def _validation_claim(
    config: Mapping[str, Any],
    validation_rows: Sequence[Mapping[str, Any]],
    artifact_index: Mapping[str, Mapping[str, Any]],
    gate: str,
) -> ClaimMatrixRow:
    counts = dict(sorted(Counter(str(row["status"]) for row in validation_rows).items()))
    return ClaimMatrixRow(
        "C-VALIDATION-01",
        f"The immutable validation ledger for release {config['run']['run_id']} records status counts {counts} and satisfies the required release gate.",
        "simulation",
        f"{config['run']['selected_scenario_ids']} / all released replicates",
        _artifact_tokens(artifact_index, "validation/validation_issue.parquet", "validation/validation_metadata.json"),
        "validation status census / fail-closed required-check registry",
        "none",
        f"required checks={len(config['validation']['required_check_ids'])}",
        "A passed benchmark release gate is not a jurisdictional compliance finding.",
        gate,
        "supported",
    )


def _reproducibility_claim(
    config: Mapping[str, Any],
    reproducibility: Mapping[str, Any],
    artifact_index: Mapping[str, Mapping[str, Any]],
    gate: str,
) -> ClaimMatrixRow:
    matched = bool(reproducibility.get("semantic_match")) and bool(reproducibility.get("byte_match"))
    return ClaimMatrixRow(
        "C-REPRODUCIBILITY-01",
        (
            "A separately orchestrated clean rerun matched the release's scoped semantic and byte-level reproducibility checks."
            if matched
            else "The release does not establish both semantic and byte-level clean-rerun reproducibility."
        ),
        "simulation",
        f"{config['run']['selected_scenario_ids']} / all released replicates",
        _artifact_tokens(artifact_index, "provenance/reproducibility.json"),
        "deterministic digest equality / domain-separated SHA-256",
        "none",
        str(reproducibility.get("comparison_scope", "declared scope")),
        "The recorded scope may exclude final self-referential manifest controls as documented.",
        gate,
        "supported" if matched else "not_supported",
    )


def _paired_claim_rows(
    comparison_rows: Sequence[Mapping[str, Any]],
    artifact_index: Mapping[str, Mapping[str, Any]],
    config: Mapping[str, Any],
    gate: str,
    comparison_path: str,
) -> tuple[ClaimMatrixRow, ...]:
    if not comparison_rows:
        return ()
    artifacts = _artifact_tokens(
        artifact_index,
        comparison_path,
        "validation/validation_issue.parquet",
    )
    rows: list[ClaimMatrixRow] = []
    for item in sorted(comparison_rows, key=lambda row: str(row["comparison_id"])):
        status_value = str(item.get("status", "pass"))
        status = "supported" if status_value == "pass" else "diagnostic_only"
        metric_name = str(item["metric_name"] if "metric_name" in item else item["metric_key"])
        comparator = str(item.get("comparator_profile_id") or item.get("baseline_condition_id") or "none")
        treatment = str(item.get("proposed_profile_id") or item.get("treatment_condition_id") or "none")
        effect = item.get("mean_difference")
        if effect is None:
            effect = item.get("proposed_minus_comparator")
        replicate_ids = item.get("paired_replicate_ids", ())
        rows.append(
            ClaimMatrixRow(
                _claim_id("COMPARISON", item["comparison_id"]),
                (
                    ("" if status == "supported" else "Diagnostic only; paired comparison requirements were not satisfied. ")
                    + f"For {metric_name}, {treatment} minus {comparator} was {_number(effect)} over paired replicates {_join_ints(replicate_ids)}."
                ),
                "simulation",
                f"{item.get('scenario_id', config['run']['scenario_id'])} / paired replicates {_join_ints(replicate_ids)}",
                artifacts,
                f"{metric_name} / paired common-random-number effect",
                f"{comparator} versus {treatment}",
                f"common_random_group={item.get('common_random_group', 'not_recorded')}",
                str(item.get("reason", "bounded to declared baseline and scenarios")),
                gate,
                status,
            )
        )
    return tuple(rows)


def _write_claim_matrix(root: Path, rows: Sequence[ClaimMatrixRow]) -> Path:
    path = root / "claim_matrix.csv"
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CLAIM_MATRIX_COLUMNS)
    for row in rows:
        writer.writerow(row.csv_row())
    atomic_write_bytes(path, buffer.getvalue().encode("utf-8"))
    return path


def _write_metric_trace(
    root: Path,
    metrics: Sequence[Mapping[str, Any]],
    provenance: Sequence[Mapping[str, Any]],
    artifact_index: Mapping[str, Mapping[str, Any]],
    gate: str,
) -> Path:
    path = root / "metric_trace.csv"
    provenance_by_id = {str(row["metric_id"]): row for row in provenance}
    metric_token = _artifact_tokens(artifact_index, "metrics/run_metric.parquet")
    provenance_token = _artifact_tokens(
        artifact_index, "metrics/observation_provenance.parquet"
    )
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        (
            "metric_id",
            "run_id",
            "scenario_id",
            "replicate_id",
            "metric_name",
            "value",
            "unit",
            "standard_error",
            "ci_lower",
            "ci_upper",
            "definition_id",
            "registry_sha256",
            "estimator",
            "weighting",
            "scope_id",
            "denominator",
            "denominator_unit",
            "publication_eligible",
            "metric_artifact",
            "provenance_artifact",
            "validation_gate",
        )
    )
    for metric in sorted(metrics, key=lambda row: str(row["metric_id"])):
        item = provenance_by_id[str(metric["metric_id"])]
        writer.writerow(
            (
                metric["metric_id"], metric["run_id"], metric["scenario_id"],
                metric["replicate_id"], metric["metric_name"], metric["value"],
                metric["unit"], _csv_optional(metric.get("standard_error")),
                _csv_optional(metric.get("ci_lower")), _csv_optional(metric.get("ci_upper")),
                item["definition_id"], item["registry_sha256"], metric["estimator"],
                metric["weighting"], item["scope_id"], _csv_optional(item.get("denominator")),
                item["denominator_unit"], _bool_text(bool(item["publication_eligible"])),
                metric_token, provenance_token, gate,
            )
        )
    atomic_write_bytes(path, buffer.getvalue().encode("utf-8"))
    return path


def _write_data_card(
    root: Path,
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    artifacts: Sequence[StoredArtifact],
    validations: Sequence[Mapping[str, Any]],
    metrics: Sequence[Mapping[str, Any]],
    aggregates: Sequence[Mapping[str, Any]],
    baseline_conditions: Sequence[Mapping[str, Any]],
    reproducibility: Mapping[str, Any],
    inventory_digest: str,
    claim_rows: Sequence[ClaimMatrixRow],
) -> Path:
    privacy_counts = dict(sorted(Counter(item.privacy_class for item in artifacts).items()))
    status_counts = dict(sorted(Counter(str(row["status"]) for row in validations).items()))
    metric_domains = dict(sorted(Counter(str(row["metric_domain"]) for row in metrics).items()))
    supported_maturity = [
        row.claim_id
        for row in claim_rows
        if row.claim_id.startswith("C-MATURITY-") and row.claim_status == "supported"
    ]
    q = claim_contract["executed_operations"]
    q_text = "not executed" if q is None else str(q)
    card = f"""# HTGL Federated Smart-Grid Governance Benchmark Data Card

## Source Hierarchy

`Prompts/2-Dataset` is the controlling implementation contract. `Prompts/1-Dataset` is background only where it reinforces that contract. The resolved configuration, locked Arrow schemas, source register, and final manifest bind this release.

## Dataset Purpose

This release contains governance-complete federated smart-grid benchmark artifacts: physical and context streams, custody-aware catalog records, exact or explicitly named arrival models, workflow traces, normalized causal edges, evaluator truth, evidence fixtures, observer projections, probability samples, validation, and metrics. It can supply optional replay workloads, but the generator does not implement HTGL consensus, a production ledger, physical erasure, legal enforcement, or utility deployment.

## Release Identity And Scale

- Run ID: `{config['run']['run_id']}`
- Contract version: `{config['run']['contract_version']}`
- Release profile: `{config['output']['release_profile_id']}`
- Config SHA-256: `{config['config_sha256']}`
- Report source inventory SHA-256: `{inventory_digest}`
- Full stochastic replicates: `{config['run']['replicate_count']}`
- `N` represented population: `{claim_contract['represented_population']}`
- `n` materialized governance-event rows: `{claim_contract['materialized_rows']}`
- Configured materialized-row target: `{claim_contract['materialized_row_target']}`
- `q` downstream replay operations actually observed: `{q_text}`
- Configured replay target: `{_text_or_none(claim_contract['executed_operation_target'])}`

`N`, `n`, and `q` are separate quantities. Represented exposure is neither a materialized user population nor an executed workload.

## Provenance And Privacy

- Source-label counts: `{_source_label_summary(config)}`
- Controlled synthetic physical source IDs: `{_join(config['physical']['calibration_source_ids'])}`
- Typed source registry: `provenance/sources.json`, with a public provenance projection at `publication/provenance/source_registry.json`
- Artifact privacy classes in the immutable report-source inventory: `{privacy_counts}`
- Authoritative storage: typed Arrow schemas and Parquet/ZSTD. JSONL and other adapters are compatibility projections only.

The release is promoted as three physically separate sibling bundles: public, evaluator-only, and restricted operational. Each has its own artifact manifest, root manifest, byte digest, ownership marker, and permitted privacy classes. No combined release directory or archive is produced. Evaluator-only policy, anomaly, evidence-sufficiency, closure, and sampling truth remains separated from public observer and adapter outputs. Public report generation rejects sealed field names and protected pair identifiers.

## Physical Backends

- Profile class: `controlled_procedural_synthetic`
- Backend: `{config['physical']['backend']}` version `{config['physical']['backend_version']}`
- Analytic state backend: `{config['physical']['solver_backend']}`
- Controlled synthetic parameter bundle: `{config['physical']['calibration_bundle_id']}`
- Interval: `{config['physical']['interval_seconds']}` seconds in `{config['run']['time_zone']}`

All currently executable physical modes are controlled procedural synthetic profiles. `opensynth_style_synthetic` and `smart_ds_style_synthetic` are internal formula/topology styles, not OpenSynth, Faraday, SMART-DS, or SimBench integrations. No imported physical benchmark, learned external model, OpenDSS, GridLAB-D, pandapower, or other external power-flow solver was executed. Physical validity is limited to {CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE}.

## Governance Semantics

- Workflow families: `{_join(config['workflows']['families'])}`
- Workflow definition versions: `{_mapping_text(config['workflows']['definition_versions'])}`
- Policy profile: `{config['policy']['profile_id']}` version `{config['policy']['profile_version']}`
- Policy evaluator: `{config['policy']['evaluator_profile']}` with golden suite `{config['policy']['golden_suite_id']}`
- Causal dependencies are normalized in authoritative event-edge Parquet records.
- Policy labels are outputs of the configured experimental policy profile, not legal findings.

## Observer Views

- Visibility DSL: `{config['observer']['visibility_dsl_profile_id']}`
- Profiles: `{_join(config['observer']['observer_profile_ids'])}`
- Leakage scanner: `{config['observer']['leakage_scan_profile_id']}`

Institutional and public views contain only policy-visible, delayed, lossy, redacted, or collusion-composed projections. Omniscient evaluator mappings are stored separately.

## Evidence Boundary

Configured receipt profiles: `{_join(config['evidence']['receipt_profiles'])}`. Proof limit: {config['evidence']['proof_limit_statement']}

Receipts evaluate obligation coverage, validity, timeliness, contradiction, and modeled sufficiency under synthetic evidence profiles. They do not establish physical deletion or legal enforcement.

## Quality And Reproducibility

- Validation status counts: `{status_counts}`
- Metric rows by domain: `{metric_domains}`
- Replicate aggregate rows: `{len(aggregates)}`
- Executed baseline/ablation conditions: `{len(baseline_conditions)}`
- Semantic clean-rerun match: `{_bool_text(bool(reproducibility.get('semantic_match')))}`
- Byte-level clean-rerun match: `{_bool_text(bool(reproducibility.get('byte_match')))}`
- Supported maturity claim IDs: `{_join(supported_maturity) if supported_maturity else 'none'}`

Every reported metric value is linked by `claim_matrix.csv` and `metric_trace.csv` to a metric definition, estimator, weighting rule, immutable artifact checksum, and validation gate.

## Intended Uses

- Benchmark policy, workflow, anomaly, evidence, observer, and sampling logic under declared synthetic profiles.
- Compare named temporal, structural, anomaly, observer, and sampling baselines with common random numbers where configured.
- Evaluate design-based recovery of known synthetic totals only when inclusion probabilities and estimator eligibility pass.
- Replay explicitly materialized workloads into a separate implementation or simulator and report only the observed `q`.

## Prohibited Interpretations

- Do not interpret represented `N` as throughput, user handling, row materialization, or downstream execution.
- Do not infer physical deletion from receipts, hashes, signatures, Merkle inclusions, or replica attestations.
- Do not promote policy-profile outputs into jurisdiction-wide compliance findings.
- Do not infer production HTGL capacity, utility deployment, or ledger anchoring from generator artifacts.
- Do not infer calibrated physical fidelity, external-backend conformance, or external solver convergence from controlled procedural synthetic physical records.
- Do not assert scientific priority without a separate systematic review and claim-level evidence package.
"""
    path = root / "data_card.md"
    atomic_write_bytes(path, card.encode("utf-8"))
    return path


def _write_model_card(
    root: Path,
    config: Mapping[str, Any],
    metrics_metadata: Mapping[str, Any],
    validation_metadata: Mapping[str, Any],
    claim_rows: Sequence[ClaimMatrixRow],
    inventory_digest: str,
) -> Path:
    unsupported = [
        row.claim_id
        for row in claim_rows
        if row.claim_id.startswith("C-MATURITY-") and row.claim_status != "supported"
    ]
    card = f"""# HTGL Dataset Generator Model Card

## Contract And Evidence Binding

- Run ID: `{config['run']['run_id']}`
- Release profile: `{config['output']['release_profile_id']}`
- Config SHA-256: `{config['config_sha256']}`
- Immutable report-source inventory SHA-256: `{inventory_digest}`
- Metric registry: `{metrics_metadata['metric_registry_id']}` version `{metrics_metadata['metric_registry_version']}` SHA-256 `{metrics_metadata['metric_registry_sha256']}`
- Validation release eligible: `{_bool_text(bool(validation_metadata['release_eligible']))}`

This card describes generation and evaluation models. It does not describe an HTGL consensus, ledger, erasure, enforcement, or utility-deployment implementation.

The release profile accepts only the controlled procedural physical backend and `controlled_synthetic` source labels. The typed source registry records generator-owned definitions and transformations; it does not substitute synthetic identifiers for external calibration sources or licence permissions.

## Arrival Models

Configured classes: `{_join(config['arrivals']['model_classes'])}`. Conditioned totals use multinomial allocation proportional to integrated intensity. Unconditioned NHPP bins use exact Poisson draws and intensity-respecting within-bin times. MMPP and Hawkes modes are enabled only with their pinned stability and diagnostic contracts. The rounded-Gaussian/uniform-bin approximation remains a named negative control and is excluded from publication claims by default.

## Workflow Automata

Families: `{_join(config['workflows']['families'])}`. Definition versions: `{_mapping_text(config['workflows']['definition_versions'])}`. Events are state transitions with workflow instances, normalized dependency edges, computed roots and causal depths, allowed terminal/open-horizon states, and typed side effects. Legal-basis labels are controlled experimental registry values, not compliance determinations.

## Policy Oracle

Profile `{config['policy']['profile_id']}` version `{config['policy']['profile_version']}` uses evaluator `{config['policy']['evaluator_profile']}`, conflict strategy `{config['policy']['conflict_strategy']}`, and independently authored golden suite `{config['policy']['golden_suite_id']}`. Conditions operate over normalized actor, relationship, object, purpose, jurisdiction, consent, retention, erasure, and effective-time facts without arbitrary Python evaluation.

## Counterfactual Anomaly Engine

Invariant registry `{config['anomaly']['invariant_registry_id']}` version `{config['anomaly']['invariant_registry_version']}` and edit grammar `{config['anomaly']['edit_grammar_id']}` version `{config['anomaly']['edit_grammar_version']}` define target invariants, protected invariants, edit costs, and bounded search. Accepted episodes fail the target while preserving declared non-target invariants. Random corruption remains a separate baseline.

## Evidence Compiler

Obligation bundle `{config['evidence']['obligation_template_bundle_id']}` version `{config['evidence']['obligation_template_bundle_version']}` is expanded before receipts are generated. Receipt bundle `{config['evidence']['receipt_profile_bundle_id']}` version `{config['evidence']['receipt_profile_bundle_version']}` uses canonicalization `{config['evidence']['canonicalization_profile_id']}` and synthetic key profile `{config['evidence']['synthetic_key_profile_id']}`. Sufficiency is independently recomputed for coverage, validity, timeliness, contradictions, and missing dependencies. ML-removal profiles are `{_join(config['evidence']['ml_removal_profile_ids']) if config['evidence']['ml_removal_profile_ids'] else 'disabled'}`.

## Observer Projection DSL

Visibility DSL `{config['observer']['visibility_dsl_profile_id']}` compiles full, role-based, delayed, lossy, adversarial-omission, and collusion views from frozen facts. Leakage scan `{config['observer']['leakage_scan_profile_id']}` blocks sealed truth labels, protected identifiers, forbidden paths, and disallowed sampling internals from public outputs.

## Sampling Design

Designs: `{_join(config['sampling']['design_types'])}`. Primary units: `{_join(config['sampling']['primary_unit_types'])}`. Closure policy: `{config['sampling']['closure_policy']}`. Estimator families: `{_join(config['sampling']['estimator_families'])}`. Population estimates are emitted only for eligible probability designs; exact induced probabilities, documented repeated-design estimates, or explicit ineligibility are required.

## Validation And Metrics

The validation profile requires `{len(config['validation']['required_check_ids'])}` stable checks across schema, identity, foreign keys, time, physical state, arrivals, workflows, causal structure, policy, anomalies, evidence, observers, sampling, privacy, artifacts, and performance. Missing, failed, or not-executed mandatory checks block release. Every registered Appendix A metric is computed, explicitly justified as not applicable under its declared applicability rule, or publication-blocking as not executed. Metrics retain domain, value, unit, denominator, estimator, weighting, baseline, uncertainty, definition ID, registry digest, and execution evidence digest.

## Limitations

- Synthetic rates, relationships, physical behavior, and policy profiles remain bounded by their declared controlled synthetic parameter profiles.
- Observer and evidence conclusions concern modeled visibility and protocol feasibility, not deployed institutional behavior.
- Known-total recovery concerns synthetic represented populations and does not establish operational scalability.
- Downstream execution is absent unless separately measured replay evidence supplies `q`, implementation, hardware, software, workload digest, and result digest.
- Unsupported maturity claim IDs for this release: `{_join(unsupported) if unsupported else 'none'}`.
"""
    path = root / "model_card.md"
    atomic_write_bytes(path, card.encode("utf-8"))
    return path


def _write_quality_reports(
    root: Path,
    config: Mapping[str, Any],
    validations: Sequence[Mapping[str, Any]],
    metrics: Sequence[Mapping[str, Any]],
    aggregates: Sequence[Mapping[str, Any]],
    paired: Sequence[Mapping[str, Any]],
    baselines: Sequence[Mapping[str, Any]],
    reproducibility: Mapping[str, Any],
    inventory_digest: str,
    claims: Sequence[ClaimMatrixRow],
    artifact_index: Mapping[str, Mapping[str, Any]],
) -> tuple[Path, Path]:
    validation_summary = dict(sorted(Counter(str(row["status"]) for row in validations).items()))
    metric_summary = dict(sorted(Counter(str(row["metric_domain"]) for row in metrics).items()))
    claim_summary = dict(sorted(Counter(row.claim_status for row in claims).items()))
    public_validation = [
        {
            "check_id": row["check_id"],
            "domain": row["domain"],
            "severity": row["severity"],
            "status": row["status"],
        }
        for row in sorted(validations, key=lambda item: (str(item["check_id"]), str(item["run_id"])))
    ]
    public_metrics = [
        {
            "metric_id": row["metric_id"],
            "scenario_id": row["scenario_id"],
            "replicate_id": row["replicate_id"],
            "domain": row["metric_domain"],
            "name": row["metric_name"],
            "value": row["value"],
            "unit": row["unit"],
            "standard_error": row.get("standard_error"),
            "ci_lower": row.get("ci_lower"),
            "ci_upper": row.get("ci_upper"),
            "estimator": row["estimator"],
            "weighting": row["weighting"],
            "baseline_id": row.get("baseline_id"),
        }
        for row in sorted(metrics, key=lambda item: str(item["metric_id"]))
    ]
    payload = {
        "format": "htgl.quality-report.v2",
        "run_id": config["run"]["run_id"],
        "config_sha256": config["config_sha256"],
        "source_inventory_digest": inventory_digest,
        "validation_status_counts": validation_summary,
        "metric_domain_counts": metric_summary,
        "claim_status_counts": claim_summary,
        "replicate_aggregate_count": len(aggregates),
        "paired_metric_comparison_count": len(paired),
        "baseline_comparison_count": len(baselines),
        "reproducibility": reproducibility,
        "validation_artifact": _artifact_tokens(artifact_index, "validation/validation_issue.parquet"),
        "metric_artifact": _artifact_tokens(artifact_index, "metrics/run_metric.parquet"),
        "validations": public_validation,
        "metrics": public_metrics,
        "claim_boundary": (
            "benchmark evidence only; no legal finding, physical deletion, production ledger, "
            "utility deployment, or operational HTGL capacity inference"
        ),
    }
    json_path = root / "quality_report.json"
    atomic_write_bytes(json_path, canonical_json_bytes(payload))

    validation_table = _html_table(
        ("Check ID", "Domain", "Severity", "Status"),
        [
            (row["check_id"], row["domain"], row["severity"], row["status"])
            for row in public_validation
        ],
    )
    metric_table = _html_table(
        ("Metric ID", "Scenario", "Replicate", "Domain", "Name", "Value", "Unit", "Estimator", "Weighting"),
        [
            (
                row["metric_id"], row["scenario_id"], row["replicate_id"], row["domain"],
                row["name"], _number(row["value"]), row["unit"], row["estimator"], row["weighting"],
            )
            for row in public_metrics
        ],
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>HTGL Quality Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:90rem;margin:2rem auto;padding:0 1rem;color:#202124;line-height:1.45}}table{{border-collapse:collapse;width:100%;font-size:.86rem;margin-bottom:2rem}}th,td{{border:1px solid #c8ccd0;padding:.4rem;text-align:left;vertical-align:top}}th{{background:#eef1f3}}code{{background:#eef1f3;padding:.1rem .25rem}}.boundary{{border-left:4px solid #8b1e1e;padding:.75rem 1rem;background:#fff5f5}}</style></head>
<body><h1>HTGL Benchmark Quality Report</h1>
<p>Run <code>{escape(str(config['run']['run_id']))}</code>; config <code>{escape(str(config['config_sha256']))}</code>; immutable report-source inventory <code>{escape(inventory_digest)}</code>.</p>
<h2>Validation Summary</h2><p>{escape(str(validation_summary))}</p>{validation_table}
<h2>Metric Summary</h2><p>{escape(str(metric_summary))}</p>{metric_table}
<h2>Replicates, Baselines, And Claims</h2><ul><li>Replicate aggregate rows: {len(aggregates)}</li><li>Paired metric comparisons: {len(paired)}</li><li>Baseline comparison rows: {len(baselines)}</li><li>Claim status counts: {escape(str(claim_summary))}</li></ul>
<h2>Reproducibility</h2><p>{escape(str(reproducibility))}</p>
<h2>Traceability</h2><p>Each metric row above is keyed by metric ID in <code>metric_trace.csv</code> and by a stable claim ID in <code>claim_matrix.csv</code>. Those files bind metric definitions, estimators, weights, source artifact IDs, SHA-256 checksums, assumptions, limitations, and validation gates.</p>
<h2>Claim Boundary</h2><p class="boundary">Generated benchmark evidence does not establish a legal finding, physical deletion, production ledger operation, utility deployment, or operational HTGL capacity. Represented N, materialized n, and downstream replay q remain distinct.</p>
</body></html>\n"""
    html_path = root / "quality_report.html"
    atomic_write_bytes(html_path, html.encode("utf-8"))
    return json_path, html_path


def _write_baseline_reports(
    root: Path,
    comparisons: Sequence[Mapping[str, Any]],
) -> tuple[Path, Path]:
    csv_path = root / "baseline_ablation_report.csv"
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    columns = (
        "scenario_id", "family", "metric_name", "comparator_profile_id",
        "proposed_profile_id", "comparator_role", "common_random_group",
        "paired_replicate_ids", "pair_count", "proposed_minus_comparator",
        "standard_error", "ci_lower", "ci_upper", "standardized_effect_size",
        "status", "reason",
    )
    writer.writerow(columns)
    for item in sorted(comparisons, key=lambda row: str(row["comparison_id"])):
        writer.writerow(
            (
                item["scenario_id"], item["family"], item["metric_name"],
                item["comparator_profile_id"], item["proposed_profile_id"],
                item["comparator_role"], item["common_random_group"],
                _join_ints(item["paired_replicate_ids"]), item["pair_count"],
                _csv_optional(item.get("mean_difference")),
                _csv_optional(item.get("empirical_standard_error")), _csv_optional(item.get("ci_lower")),
                _csv_optional(item.get("ci_upper")), _csv_optional(item.get("standardized_effect_size")),
                item["status"], item["reason"],
            )
        )
    atomic_write_bytes(csv_path, buffer.getvalue().encode("utf-8"))
    status_counts = dict(sorted(Counter(str(row["status"]) for row in comparisons).items()))
    markdown = f"""# P8 Baseline And Ablation Report

- Immutable comparison rows: `{len(comparisons)}`
- Status counts: `{status_counts}`

Every effect is proposed minus comparator and retains the pinned common-random-number group and independently orchestrated replicate IDs. Insufficient pairs remain diagnostic and receive no fabricated standard error, confidence interval, or standardized effect.

The rounded-Gaussian/uniform-bin method is a named defective negative control, not an exact Poisson or NHPP implementation. Sampling controls without valid inclusion probabilities never produce population estimates. These comparisons concern generated benchmark artifacts and do not establish legal findings, physical deletion, operational HTGL capacity, ledger operation, utility deployment, or materialization of represented `N`.
"""
    markdown_path = root / "baseline_ablation_report.md"
    atomic_write_bytes(markdown_path, markdown.encode("utf-8"))
    return csv_path, markdown_path


def _verify_source_inventory(
    root: Path,
    artifacts: Sequence[StoredArtifact],
    manifest_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    artifact_by_path = {item.relative_path: item for item in artifacts}
    rows_by_path = {str(row["relative_path"]): row for row in manifest_rows}
    if len(artifact_by_path) != len(artifacts) or len(rows_by_path) != len(manifest_rows):
        raise ArtifactIntegrityError("publication report source inventory contains duplicate paths")
    if set(artifact_by_path) != set(rows_by_path):
        raise ArtifactIntegrityError("publication report source artifacts and manifest rows disagree")
    for relative, artifact in sorted(artifact_by_path.items()):
        path = root / Path(relative)
        if not path.is_file():
            raise ArtifactIntegrityError(f"publication report source artifact is missing: {relative}")
        payload = path.read_bytes()
        if len(payload) != artifact.stored_bytes or sha256_hex(payload) != artifact.sha256:
            raise ArtifactIntegrityError(
                f"publication report source artifact changed after inventory: {relative}"
            )
        row = rows_by_path[relative]
        if str(row["sha256"]) != artifact.sha256:
            raise ArtifactIntegrityError(
                f"publication report source manifest digest disagrees for {relative}"
            )
    return rows_by_path


def _validate_report_inputs(
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    validations: Sequence[Mapping[str, Any]],
    metrics: Sequence[Mapping[str, Any]],
    provenance: Sequence[Mapping[str, Any]],
    executions: Sequence[Mapping[str, Any]],
    validation_metadata: Mapping[str, Any],
    metrics_metadata: Mapping[str, Any],
) -> None:
    if not bool(validation_metadata.get("release_eligible")):
        raise ArtifactIntegrityError("publication reports require an eligible immutable validation ledger")
    failed = [
        (row["check_id"], row["status"])
        for row in validations
        if row["status"] not in {"pass", "not_applicable"}
    ]
    if failed:
        raise ArtifactIntegrityError(f"publication reports cannot use failed validation rows {failed}")
    required = set(config["validation"]["required_check_ids"])
    observed = {str(row["check_id"]) for row in validations}
    missing = sorted(required - observed)
    if missing:
        raise ArtifactIntegrityError(f"publication report validation ledger omits required checks {missing}")
    metric_ids = {str(row["metric_id"]) for row in metrics}
    provenance_ids = {str(row["metric_id"]) for row in provenance}
    if not metric_ids or metric_ids != provenance_ids or len(provenance_ids) != len(provenance):
        raise ArtifactIntegrityError("publication metrics and observation provenance do not reconcile one-to-one")
    output_metric_ids = {
        str(metric_id)
        for row in executions
        for metric_id in row["output_metric_ids"]
        if row["status"] == "computed"
    }
    if not metric_ids <= output_metric_ids:
        raise ArtifactIntegrityError(
            f"publication metrics lack passed execution evidence {sorted(metric_ids-output_metric_ids)}"
        )
    if int(metrics_metadata.get("run_metric_count", -1)) != len(metrics):
        raise ArtifactIntegrityError("metrics metadata row count disagrees with immutable run_metric Parquet")
    if metrics_metadata.get("metric_registry_sha256") != provenance[0]["registry_sha256"]:
        raise ArtifactIntegrityError("metrics metadata registry digest disagrees with provenance")
    if bool(claim_contract.get("legal_compliance_claim")) or bool(claim_contract.get("real_deletion_claim")):
        raise ArtifactIntegrityError("publication claim guard exceeds the generator boundary")


def _validate_claim_contract_against_artifacts(
    config: Mapping[str, Any],
    claim_contract: Mapping[str, Any],
    artifacts: Sequence[StoredArtifact],
    replay: Mapping[tuple[str, int], DownstreamReplayObservation] | None,
) -> None:
    event_rows = sum(
        int(item.record_count or 0)
        for item in artifacts
        if item.relative_path.startswith("canonical/events/")
    )
    observed_q = None if not replay else sum(
        item.executed_operation_count for item in replay.values()
    )
    expected = {
        "represented_population": int(config["claim_scale"]["represented_population"]),
        "materialized_rows": event_rows,
        "materialized_row_target": int(config["claim_scale"]["materialized_row_target"]),
        "executed_operations": observed_q,
        "executed_operation_target": config["claim_scale"]["executed_operation_target"],
    }
    disagreements = {
        key: {"claim_guard": claim_contract.get(key), "immutable_evidence": value}
        for key, value in expected.items()
        if claim_contract.get(key) != value
    }
    if disagreements:
        raise ArtifactIntegrityError(
            f"N/n/q claim guard disagrees with immutable report-source artifacts: {disagreements}"
        )


def _read_parquet_artifact(
    root: Path,
    artifact_index: Mapping[str, Mapping[str, Any]],
    relative: str,
) -> tuple[dict[str, Any], ...]:
    if relative not in artifact_index:
        raise ArtifactIntegrityError(f"publication reports require immutable artifact {relative}")
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ArtifactIntegrityError("pyarrow is required to compile publication reports") from exc
    table = pq.read_table(root / Path(relative))
    return tuple(dict(row) for row in table.to_pylist())


def _read_optional_parquet_artifact(
    root: Path,
    artifact_index: Mapping[str, Mapping[str, Any]],
    relative: str,
) -> tuple[dict[str, Any], ...]:
    if relative not in artifact_index:
        return ()
    return _read_parquet_artifact(root, artifact_index, relative)


def _read_json_artifact(
    root: Path,
    artifact_index: Mapping[str, Mapping[str, Any]],
    relative: str,
) -> dict[str, Any]:
    if relative not in artifact_index:
        raise ArtifactIntegrityError(f"publication reports require immutable artifact {relative}")
    payload = json.loads((root / Path(relative)).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ArtifactIntegrityError(f"publication report source {relative} must be a JSON object")
    return payload


def _validation_gate(
    config: Mapping[str, Any],
    validation_rows: Sequence[Mapping[str, Any]],
) -> str:
    statuses: dict[str, set[str]] = {}
    for row in validation_rows:
        statuses.setdefault(str(row["check_id"]), set()).add(str(row["status"]))
    required = tuple(str(item) for item in config["validation"]["required_check_ids"])
    invalid = {
        check_id: sorted(statuses.get(check_id, {"missing"}))
        for check_id in required
        if not statuses.get(check_id) or not statuses[check_id] <= {"pass", "not_applicable"}
    }
    if invalid:
        raise ArtifactIntegrityError(f"publication validation gate is not closed: {invalid}")
    return "PASS:" + ",".join(required)


def _artifact_tokens(
    artifact_index: Mapping[str, Mapping[str, Any]],
    *paths: str,
) -> str:
    tokens: list[str] = []
    for relative in sorted(set(paths)):
        if relative not in artifact_index:
            raise ArtifactIntegrityError(f"claim trace requires missing artifact {relative}")
        row = artifact_index[relative]
        tokens.append(
            f"{row['artifact_id']}|{relative}|sha256={row['sha256']}"
        )
    return ";".join(tokens)


def _paths_with_prefix(
    artifact_index: Mapping[str, Mapping[str, Any]], prefix: str
) -> tuple[str, ...]:
    paths = tuple(sorted(path for path in artifact_index if path.startswith(prefix)))
    if not paths:
        raise ArtifactIntegrityError(f"claim trace has no artifacts under {prefix}")
    return paths


def _metric_assumptions(item: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    scope = str(item["scope_json"])
    _reject_public_field_leakage((scope,))
    return (
        f"scope={scope}; denominator={_csv_optional(item.get('denominator'))} "
        f"{item['denominator_unit']}; source_labels={_source_label_summary(config)}"
    )


def _metric_limitations(item: Mapping[str, Any], status: str) -> str:
    prefix = "Publication-eligible under the recorded release gate. " if status == "supported" else "Not publication-eligible. "
    return (
        prefix
        + str(item["uncertainty_reason"])
        + "; result is scoped to generated benchmark artifacts and declared external measurements"
    )


def _metric_evidence_class(metric: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    if metric["metric_domain"] == "sampling" and int(config["claim_scale"]["represented_population"]) >= 100_000_000:
        return "represented-scale"
    if metric["metric_name"] in {"deterministic_digest_match", "manifest_coverage"}:
        return "mathematical"
    return "simulation"


def _aggregate_evidence_class(item: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    if item["metric_domain"] == "sampling" and int(config["claim_scale"]["represented_population"]) >= 100_000_000:
        return "represented-scale"
    return "simulation"


def _claim_id(namespace: str, identity: Any) -> str:
    digest = domain_sha256("publication-claim-id-v1", {"namespace": namespace, "identity": str(identity)})
    return f"C-{namespace}-{digest[:16].upper()}"


def _interval_text(row: Mapping[str, Any]) -> str:
    lower = row.get("ci_lower")
    upper = row.get("ci_upper")
    standard_error = row.get("standard_error")
    if lower is not None and upper is not None:
        return f" with confidence interval [{_number(lower)}, {_number(upper)}]"
    if standard_error is not None:
        return f" with standard error {_number(standard_error)}"
    return ""


def _aggregate_uncertainty_text(row: Mapping[str, Any]) -> str:
    if row.get("ci_lower") is not None and row.get("ci_upper") is not None:
        return (
            f", empirical standard error {_number(row.get('empirical_standard_error'))}, "
            f"and {_number(float(row['confidence_level']) * 100.0)} percent interval "
            f"[{_number(row['ci_lower'])}, {_number(row['ci_upper'])}]"
        )
    return ""


def _source_label_summary(config: Mapping[str, Any]) -> str:
    return str(dict(sorted(Counter(str(value) for value in config["source_labels"].values()).items())))


def _require_nonempty_replay_labels(
    item: DownstreamReplayObservation, key: tuple[str, int]
) -> None:
    for label in (
        "implementation_id",
        "implementation_version",
        "software_profile_id",
        "hardware_profile_id",
    ):
        if not str(getattr(item, label)).strip():
            raise ArtifactIntegrityError(f"downstream replay key={key} has empty {label}")


def _validate_public_report_content(path: Path) -> None:
    if path.suffix.lower() not in {".md", ".html", ".json", ".csv"}:
        return
    text = path.read_text(encoding="utf-8")
    validate_publication_wording(text)
    _reject_public_field_leakage((text,))


def _reject_public_field_leakage(values: Iterable[Any]) -> None:
    lowered = "\n".join(str(value) for value in values).lower()
    leaked = [field for field in PUBLIC_REPORT_FORBIDDEN_FIELDS if field in lowered]
    if leaked:
        raise ArtifactIntegrityError(
            f"public report content exposes forbidden evaluator field names {sorted(leaked)}"
        )


def _html_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    head = "".join(f"<th>{escape(str(item))}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _number(value: Any) -> str:
    if value is None:
        return "not estimated"
    number = float(value)
    if not math.isfinite(number):
        raise ArtifactIntegrityError(f"publication report cannot contain non-finite number {value!r}")
    return format(number, ".12g")


def _csv_optional(value: Any) -> str:
    return "not_estimated" if value is None else str(value)


def _join(values: Iterable[Any]) -> str:
    return ", ".join(str(value) for value in values)


def _join_ints(values: Iterable[Any]) -> str:
    return ",".join(str(int(value)) for value in values)


def _mapping_text(values: Mapping[str, Any]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items()))


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _text_or_none(value: Any) -> str:
    return "none" if value is None else str(value)
