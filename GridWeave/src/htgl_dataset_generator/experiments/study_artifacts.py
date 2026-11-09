"""Transactional Parquet/ZSTD compiler for P8 study evidence packages."""

from __future__ import annotations

from dataclasses import asdict
import csv
import hashlib
import io
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from htgl_dataset_generator._atomic import atomic_replace
from htgl_dataset_generator.artifacts.canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    canonical_json_text,
    domain_sha256,
)
from htgl_dataset_generator.artifacts.transaction import ReleaseTransaction

from .study_models import (
    StudyExecutionBuild,
    StudyPackageOptions,
    StudyPackageResult,
)
from .release_gate import (
    FinalReleaseGateResult,
    complete_staged_report_gate,
    evaluate_final_release_build,
)


class StudyPackageError(RuntimeError):
    """Raised when a study package cannot satisfy its declared package gate."""


def compile_study_evidence_package(
    build: StudyExecutionBuild,
    output_root: str | Path,
    *,
    options: StudyPackageOptions | None = None,
) -> StudyPackageResult:
    """Compile a diagnostic or publication study package transactionally."""

    settings = options or StudyPackageOptions()
    if settings.package_kind not in {"diagnostic", "publication"}:
        raise StudyPackageError("package_kind must be diagnostic or publication")
    if settings.compression_level < 1 or settings.compression_level > 22:
        raise StudyPackageError("compression_level must be in [1, 22]")
    preliminary_gate: FinalReleaseGateResult | None = None
    if settings.package_kind == "publication":
        if not build.publication_eligible:
            raise StudyPackageError(
                f"publication package blocked by {build.publication_blockers}"
            )
        if settings.condition_release_root is None:
            raise StudyPackageError(
                "publication package requires condition_release_root for independent S15 byte verification"
            )
        preliminary_gate = evaluate_final_release_build(
            build, settings.condition_release_root
        )
    if settings.package_kind == "publication" and (
        not build.run_metrics
        or not build.factor_metrics
        or not build.metric_aggregates
        or not build.validation_issues
    ):
        raise StudyPackageError(
            "publication package requires retained per-replicate metrics and validation rows"
        )
    transaction = ReleaseTransaction(
        Path(output_root),
        run_id=build.plan.study_id,
        config_sha256=build.execution_sha256,
        contract_fingerprint=build.plan.registry.sha256,
        collision_policy=settings.collision_policy,
    )
    transaction.begin()
    try:
        records = _table_records(build)
        inventory: list[dict[str, Any]] = []
        for relative, schema, rows, privacy, eligible in records:
            path = transaction.staging / relative
            _write_parquet(path, schema, rows, settings.compression_level)
            inventory.append(
                _inventory_row(
                    transaction.staging,
                    path,
                    schema_id=_schema_id(schema),
                    schema_fingerprint=_schema_fingerprint(schema),
                    record_count=len(rows),
                    privacy_class=privacy,
                    publication_eligible=eligible,
                )
            )
        report_files = _write_reports(transaction.staging, build, settings.package_kind)
        if preliminary_gate is not None:
            final_gate = complete_staged_report_gate(
                preliminary_gate, transaction.staging
            )
            report_files = (*report_files, *_write_final_gate_reports(transaction.staging, final_gate))
        for relative, privacy, eligible in report_files:
            inventory.append(
                _inventory_row(
                    transaction.staging,
                    transaction.staging / relative,
                    schema_id=None,
                    schema_fingerprint=None,
                    record_count=None,
                    privacy_class=privacy,
                    publication_eligible=eligible,
                )
            )
        _checkpoint(settings, "after_payloads", transaction.staging)
        artifact_schema = _artifact_manifest_schema()
        artifact_manifest_path = transaction.staging / "study_artifact_manifest.parquet"
        _write_parquet(
            artifact_manifest_path,
            artifact_schema,
            sorted(inventory, key=lambda row: row["relative_path"]),
            settings.compression_level,
        )
        artifact_manifest_inventory = _inventory_row(
            transaction.staging,
            artifact_manifest_path,
            schema_id=_schema_id(artifact_schema),
            schema_fingerprint=_schema_fingerprint(artifact_schema),
            record_count=len(inventory),
            privacy_class="public",
            publication_eligible=settings.package_kind == "publication",
        )
        complete_inventory = tuple(
            sorted((*inventory, artifact_manifest_inventory), key=lambda row: row["relative_path"])
        )
        byte_digest = domain_sha256(
            "P8-study-package-byte-inventory",
            [
                {
                    "relative_path": row["relative_path"],
                    "sha256": row["sha256"],
                    "stored_bytes": row["stored_bytes"],
                }
                for row in complete_inventory
            ],
        )
        semantic_digest = domain_sha256(
            "P8-study-package-semantic",
            {
                "plan_sha256": build.plan.plan_sha256,
                "execution_sha256": build.execution_sha256,
                "registry_sha256": build.plan.registry.sha256,
                "package_kind": settings.package_kind,
            },
        )
        root_manifest = {
            "format": "htgl.factorial-study-evidence-package.v1",
            "study_id": build.plan.study_id,
            "package_kind": settings.package_kind,
            "publication_eligible": build.publication_eligible,
            "publication_blockers": list(build.publication_blockers),
            "registry_id": build.plan.registry.registry_id,
            "registry_sha256": build.plan.registry.sha256,
            "plan_sha256": build.plan.plan_sha256,
            "execution_sha256": build.execution_sha256,
            "semantic_digest": semantic_digest,
            "release_byte_digest": byte_digest,
            "authoritative_storage": "parquet_zstd",
            "json_authority": False,
            "represented_population_execution_boundary": (
                "N is represented exposure, n is actually materialized benchmark rows, and q exists "
                "only for separately evidenced downstream replay."
            ),
            "claim_boundary": (
                "The package evaluates benchmark generation, estimators, and model-level evidence fixtures. "
                "It does not establish legal compliance, physical deletion, HTGL deployment capacity, or "
                "execution of represented population N."
            ),
            "operational_files_excluded_from_manifest": [
                ".htgl-generator-owned.json",
                "manifest.json",
            ],
            "artifacts": list(complete_inventory),
        }
        manifest_path = transaction.staging / "manifest.json"
        atomic_write_bytes(manifest_path, canonical_json_bytes(root_manifest))
        transaction.record_phase(
            "study_package_compiled",
            artifact_count=len(complete_inventory),
            package_kind=settings.package_kind,
            publication_eligible=build.publication_eligible,
        )
        transaction.seal_owner_marker()
        _checkpoint(settings, "before_promotion", transaction.staging)
        reused = transaction.promote(byte_digest)
        final_manifest = transaction.target / "manifest.json"
        return StudyPackageResult(
            package_root=transaction.target,
            manifest_path=final_manifest,
            manifest_sha256=hashlib.sha256(final_manifest.read_bytes()).hexdigest(),
            semantic_digest=semantic_digest,
            byte_digest=byte_digest,
            artifact_count=len(complete_inventory),
            publication_eligible=build.publication_eligible,
            reused_existing_package=reused,
        )
    except Exception as exc:
        try:
            transaction.record_phase(
                "compilation_failed", error_type=type(exc).__name__, message=str(exc)
            )
        finally:
            transaction.release_lock()
        raise


def _table_records(
    build: StudyExecutionBuild,
) -> tuple[tuple[str, Any, list[dict[str, Any]], str, bool], ...]:
    registry_rows = [
        {
            "registry_id": build.plan.registry.registry_id,
            "registry_version": build.plan.registry.version,
            "registry_sha256": build.plan.registry.sha256,
            "axis_id": axis.axis_id,
            "execution_mode": axis.execution_mode,
            "level_id": level.level_id,
            "value_json": canonical_json_text(level.value),
            "claim_eligible": level.claim_eligible,
            "required_capability": level.required_capability,
            "scale_semantics": "N=represented population;n=materialized rows;q=evidenced downstream replay only",
        }
        for axis in build.plan.registry.axes
        for level in axis.levels
    ]
    condition_rows = [
        {
            "study_id": build.plan.study_id,
            "condition_id": item.condition_id,
            "ordinal": item.ordinal,
            "design_mode": build.plan.design_mode,
            "represented_population_N": item.represented_population_N,
            "materialized_row_target_n": item.materialized_row_target_n,
            "executed_operation_target_q": item.executed_operation_target_q,
            "repetitions": item.repetitions,
            "common_random_group": item.common_random_group,
            "estimator_eligible": item.estimator_eligible,
            "feasibility_status": item.feasibility_status,
            "feasibility_reasons_json": canonical_json_text(item.feasibility_reasons),
            "factor_level_ids_json": canonical_json_text(item.factor_level_ids),
            "factor_values_json": canonical_json_text(item.factor_values),
            "projected_materialized_rows": item.projected_materialized_rows,
            "projected_stored_bytes_upper_bound": item.projected_stored_bytes_upper_bound,
        }
        for item in build.plan.conditions
    ]
    evidence_rows = [asdict(item) for item in build.replicate_evidence]
    metric_rows = [dict(item) for item in build.run_metrics]
    factor_metric_rows = [dict(item) for item in build.factor_metrics]
    aggregate_rows = [_normalize_aggregate_row(item) for item in build.metric_aggregates]
    validation_rows = [dict(item) for item in build.validation_issues]
    claim_rows = [asdict(item) for item in build.scale_claims]
    eligible = build.publication_eligible
    return (
        ("study/factor_registry.parquet", _factor_registry_schema(), registry_rows, "public", eligible),
        ("study/condition_matrix.parquet", _condition_schema(), condition_rows, "public", eligible),
        ("study/replicate_evidence.parquet", _replicate_evidence_schema(), evidence_rows, "restricted", eligible),
        ("metrics/study_run_metric.parquet", _metric_schema(), metric_rows, "public", eligible),
        ("metrics/study_factor_metric.parquet", _factor_metric_schema(), factor_metric_rows, "public", eligible),
        ("metrics/study_metric_aggregate.parquet", _aggregate_schema(), aggregate_rows, "public", eligible),
        ("validation/study_validation_issue.parquet", _validation_schema(), validation_rows, "restricted", eligible),
        ("study/scale_claim_matrix.parquet", _claim_schema(), claim_rows, "public", eligible),
    )


def _write_reports(
    root: Path,
    build: StudyExecutionBuild,
    package_kind: str,
) -> tuple[tuple[str, str, bool], ...]:
    report_root = root / "publication" / "reports"
    report_root.mkdir(parents=True, exist_ok=True)
    csv_buffer = io.StringIO(newline="")
    writer = csv.writer(csv_buffer, lineterminator="\n")
    writer.writerow(
        (
            "condition_id",
            "represented_population_N",
            "materialized_row_target_n",
            "materialized_rows_min_n",
            "materialized_rows_max_n",
            "executed_operations_sum_q",
            "retained_repetitions",
            "required_repetitions",
            "claim_status",
            "claim_statement",
        )
    )
    for claim in build.scale_claims:
        writer.writerow(
            (
                claim.condition_id,
                claim.represented_population_N,
                claim.materialized_row_target_n,
                claim.materialized_rows_min_n,
                claim.materialized_rows_max_n,
                claim.executed_operations_sum_q,
                claim.retained_repetitions,
                claim.required_repetitions,
                claim.claim_status,
                claim.claim_statement,
            )
        )
    csv_path = report_root / "scale_claim_matrix.csv"
    claim_csv_bytes = csv_buffer.getvalue().encode("utf-8")
    atomic_write_bytes(csv_path, claim_csv_bytes)
    claim_path = report_root / "claim_matrix.csv"
    atomic_write_bytes(claim_path, _full_claim_matrix_csv(build))
    supported = sum(
        claim.claim_status == "supported_represented_scale"
        for claim in build.scale_claims
    )
    markdown = f"""# HTGL Factorial Study Evidence

Package kind: `{package_kind}`. Publication eligible: `{str(build.publication_eligible).lower()}`.

The factor design is `{build.plan.design_mode}`: {build.plan.design_scope_statement}

## Scale Semantics

`N` is represented population/exposure. `n` is the configured materialization target and the separately recorded actual materialized governance-event row count. `q` is populated only by separately evidenced downstream replay; a configured target is not execution evidence.

## Evidence Summary

| Conditions | Full-factorial cardinality | Selected design rows | Required repetitions | Supported represented-scale claims | q interpretation |
| ---: | ---: | ---: | ---: | ---: | --- |
| {len(build.plan.conditions)} | {build.plan.full_factorial_condition_count} | {build.plan.selected_condition_count} | {build.plan.required_repetitions} | {supported} | downstream replay only |

Caption: every condition-level result is interpreted using represented `N`, actual/configured materialized `n`, and separately evidenced replay `q`; no column is interchangeable with another.

## Release Gate

Blockers: `{canonical_json_text(build.publication_blockers)}`

This package does not claim legal compliance, physical deletion, operational HTGL capacity, or execution/materialization of represented population `N`.
"""
    _assert_report_claim_discipline(markdown)
    markdown_path = report_root / "study_report.md"
    atomic_write_bytes(markdown_path, markdown.encode("utf-8"))
    json_payload = {
        "format": "htgl.factorial-study-report.v1",
        "study_id": build.plan.study_id,
        "package_kind": package_kind,
        "publication_eligible": build.publication_eligible,
        "publication_blockers": list(build.publication_blockers),
        "represented_population_symbol": "N",
        "materialized_rows_symbol": "n",
        "executed_operations_symbol": "q",
        "condition_count": len(build.plan.conditions),
        "replicate_ledger_count": len(build.replicate_evidence),
        "metric_row_count": len(build.run_metrics),
        "factor_metric_row_count": len(build.factor_metrics),
        "metric_aggregate_row_count": len(build.metric_aggregates),
        "validation_row_count": len(build.validation_issues),
        "claim_count": len(build.scale_claims),
        "execution_sha256": build.execution_sha256,
        "json_authority": False,
    }
    json_path = report_root / "study_report.json"
    atomic_write_bytes(json_path, canonical_json_bytes(json_payload))
    _write_study_cards(report_root, build, package_kind)
    publication_items = {
        "format": "htgl.publication-item-lineage.v1",
        "study_id": build.plan.study_id,
        "figure_count": 0,
        "figure_absence_reason": (
            "No paper figure is declared by this immutable study package; adding one requires "
            "a source-digest-bound publication item and a new package digest."
        ),
        "items": [
            _publication_item(
                root, "T-SCALE-CLAIMS", "table",
                "publication/reports/claim_matrix.csv",
                ("study/scale_claim_matrix.parquet",),
            ),
            _publication_item(
                root, "T-METRIC-AGGREGATES", "table",
                "publication/reports/quality_report.json",
                ("metrics/study_metric_aggregate.parquet", "metrics/study_run_metric.parquet"),
            ),
            _publication_item(
                root, "T-VALIDATION-SUMMARY", "table",
                "publication/reports/quality_report.json",
                ("validation/study_validation_issue.parquet",),
            ),
        ],
    }
    publication_items_path = report_root / "publication_items.json"
    atomic_write_bytes(publication_items_path, canonical_json_bytes(publication_items))
    return (
        ("publication/reports/claim_matrix.csv", "public", build.publication_eligible),
        ("publication/reports/data_card.md", "public", build.publication_eligible),
        ("publication/reports/license.md", "public", build.publication_eligible),
        ("publication/reports/limitations.md", "public", build.publication_eligible),
        ("publication/reports/model_card.md", "public", build.publication_eligible),
        ("publication/reports/publication_items.json", "public", build.publication_eligible),
        ("publication/reports/quality_report.json", "public", build.publication_eligible),
        ("publication/reports/scale_claim_matrix.csv", "public", build.publication_eligible),
        ("publication/reports/study_report.md", "public", build.publication_eligible),
        ("publication/reports/study_report.json", "public", build.publication_eligible),
        ("publication/reports/threat_model.md", "public", build.publication_eligible),
    )


def _full_claim_matrix_csv(build: StudyExecutionBuild) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    columns = (
        "claim_id", "condition_id", "evidence_class", "claim_text",
        "represented_population_N", "materialized_row_target_n",
        "materialized_rows_min_n", "materialized_rows_max_n",
        "executed_operations_sum_q", "retained_repetitions", "required_repetitions",
        "validation_gate", "statistical_gate", "artifact_gate",
        "reproducibility_gate", "claim_status", "prohibited_interpretation",
    )
    writer.writerow(columns)
    for claim in build.scale_claims:
        row = asdict(claim)
        row["evidence_class"] = claim.claim_class
        row["claim_text"] = claim.claim_statement
        writer.writerow(tuple(row.get(column) for column in columns))
    return buffer.getvalue().encode("utf-8")


def _write_study_cards(
    root: Path,
    build: StudyExecutionBuild,
    package_kind: str,
) -> None:
    executed = tuple(
        row for row in build.replicate_evidence if row.execution_status == "executed"
    )
    represented = sorted({row.represented_population_N for row in executed})
    materialized = sorted({row.materialized_row_target_n for row in executed})
    arrival_modes = sorted(
        {
            str(condition.factor_values["arrival_model"])
            for condition in build.plan.conditions
            if condition.feasibility_status == "eligible"
        }
    )
    data_card = f"""# HTGL Factorial Study Data Card

## Source Hierarchy

`Prompts/2-Dataset` controls this study. `Prompts/1-Dataset` is background only where it reinforces that contract. This card is generated from retained study evidence; manual spreadsheet values are not accepted.

## Purpose And Boundary

The package evaluates generated federated smart-grid governance benchmark artifacts, model diagnostics, observer projections, evidence fixtures, dependency-closed probability samples, and named baselines. It does not implement HTGL consensus, operational ledgers, physical erasure, legal enforcement, or utility deployment.

## Scale Semantics

- Represented populations `N`: `{represented}`
- Materialized-row targets `n`: `{materialized}`
- Executed downstream operations `q`: recorded only when separately measured replay evidence is retained
- Retained executed replicates: `{len(executed)}`

`N`, `n`, and `q` are never interchangeable. A represented population is not a materialized or executed workload.

## Storage, Privacy, And Provenance

Authoritative study tables are typed Arrow schemas stored as Parquet/ZSTD. JSON is used only for manifests and reports; JSONL adapters remain compatibility projections. Condition-level S15 releases separate evaluator-only truth from public projections and bind source bytes through SHA-256 manifests.

## Evidence Boundary

Policy labels are experimental policy-profile outputs. Receipt, signature, Merkle, and replica-attestation fixtures evaluate modeled protocol properties under declared evidence assumptions; they do not demonstrate physical deletion or legal compliance.

## Intended Use

Use this package only for claims whose claim-matrix row is supported and whose validation, statistical, artifact, and reproducibility gates pass. Package kind: `{package_kind}`.
"""
    model_card = f"""# HTGL Factorial Study Model Card

## Design

- Study ID: `{build.plan.study_id}`
- Plan SHA-256: `{build.plan.plan_sha256}`
- Registry SHA-256: `{build.plan.registry.sha256}`
- Design: `{build.plan.design_mode}`
- Selected design rows: `{build.plan.selected_condition_count}`
- Full-factorial cardinality: `{build.plan.full_factorial_condition_count}`
- Required independent repetitions: `{build.plan.required_repetitions}`

The selected design is interpreted exactly as declared by the plan; it is not relabelled as a full factorial.

## Mechanisms

Arrival modes represented by eligible cells: `{arrival_modes}`. Condition releases use exact/validated point-process implementations, versioned workflow automata, a safe independent policy oracle, obligation-first evidence compilation, minimal counterfactual anomalies, visibility-policy observer projections, and dependency-closed probability sampling.

## Validation And Uncertainty

Every eligible condition/replicate must retain the complete mandatory S13 registry, per-replicate S14 metrics, uncertainty aggregates, immutable S15 manifests, measured resource evidence, and a clean rerun digest comparison. Missing or not-executed evidence blocks publication.

## Claim Discipline

The study can support represented-scale simulation claims only. Operational claims require separately measured downstream replay `q` with implementation and hardware evidence. Policy-profile decisions are not jurisdiction-wide legal findings.
"""
    limitations = """# Limitations

- Synthetic world, custody, physical, arrival, and governance distributions remain bounded by declared controlled synthetic source labels and parameter profiles.
- Every currently executable physical mode is controlled procedural synthetic. Style modes do not import or execute OpenSynth, Faraday, SMART-DS, SimBench, OpenDSS, GridLAB-D, or pandapower, and are not evidence of calibrated fidelity, external-backend conformance, deployment realism, or solver convergence.
- Independent policy golden cases reduce circularity but do not convert experimental policy labels into legal determinations.
- Modeled receipts and attestations cannot establish physical erasure.
- Observer recoverability and leakage results apply only to the declared projection DSL, threat profiles, and protected fields.
- Known-total recovery applies to the represented synthetic population and eligible sampling design; it is not operational scalability.
- Represented `N`, materialized `n`, and separately replayed `q` remain distinct in every claim.
- No scientific-priority assertion is supported without a separate systematic review.
"""
    threat_model = """# Threat Model

## Protected Assets

Evaluator-only truth labels, anomaly pair identifiers, exact protected identifiers, sealed evidence mappings, inclusion probabilities where access is disallowed, and immutable artifact provenance.

## Adversaries And Failure Modes

- A shortcut learner attempts to recover labels from pair IDs, forbidden fields, ordering, or generation artifacts.
- An institutional observer omits, delays, redacts, replays, or colludes over visible events.
- A receipt issuer supplies late, malformed, contradictory, incomplete, substituted, or synthetically forged evidence.
- A publisher truncates samples, drops dependencies, changes report values manually, or conflates represented exposure with execution.
- A writer failure or concurrent process attempts to leave or replace a partial release.

## Controls

Named seed streams, deterministic IDs, independent truth recomputation, protected-pair separation, recursive leakage scans, dependency closure, estimator eligibility, final-byte manifests, clean reruns, report-source digests, and transactional promotion provide the declared controls.

## Residual Risk

Synthetic realism, policy scope, backend fidelity, external source licensing, and deployment behavior remain external validity limits. The package makes no legal, physical-deletion, or operational-capacity finding.
"""
    license_text = """# License Status

License status: `NO-LICENSE-GRANT`.

This generated package records its licensing status explicitly but does not grant redistribution, deployment, or third-party data rights. Copyright and database rights, if any, remain with their respective holders. External templates, calibration sources, standards mappings, and backend assets must be reviewed under their own pinned terms before redistribution.

This notice is not a legal-compliance finding or legal advice. A different release license requires an explicit owner decision, a versioned license identifier, and a newly compiled manifest.
"""
    validation_counts: dict[str, int] = {}
    for row in build.validation_issues:
        status = str(row["status"])
        validation_counts[status] = validation_counts.get(status, 0) + 1
    quality = {
        "format": "htgl.factorial-study-quality-report.v1",
        "study_id": build.plan.study_id,
        "package_kind": package_kind,
        "publication_eligible": build.publication_eligible,
        "publication_blockers": list(build.publication_blockers),
        "execution_sha256": build.execution_sha256,
        "plan_sha256": build.plan.plan_sha256,
        "executed_replicate_count": len(executed),
        "validation_status_counts": dict(sorted(validation_counts.items())),
        "run_metric_count": len(build.run_metrics),
        "factor_metric_count": len(build.factor_metrics),
        "metric_aggregate_count": len(build.metric_aggregates),
        "claim_count": len(build.scale_claims),
    }
    for name, payload in (
        ("data_card.md", data_card.encode("utf-8")),
        ("model_card.md", model_card.encode("utf-8")),
        ("limitations.md", limitations.encode("utf-8")),
        ("threat_model.md", threat_model.encode("utf-8")),
        ("license.md", license_text.encode("utf-8")),
        ("quality_report.json", canonical_json_bytes(quality)),
    ):
        atomic_write_bytes(root / name, payload)


def _publication_item(
    root: Path,
    item_id: str,
    item_kind: str,
    output_path: str,
    source_paths: Sequence[str],
) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for relative in source_paths:
        payload = (root / relative).read_bytes()
        sources.append(
            {
                "relative_path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "stored_bytes": len(payload),
            }
        )
    return {
        "item_id": item_id,
        "item_kind": item_kind,
        "output_path": output_path,
        "generation_method": "deterministic_package_compiler_v1",
        "sources": sources,
    }


def _write_final_gate_reports(
    root: Path,
    gate: FinalReleaseGateResult,
) -> tuple[tuple[str, str, bool], ...]:
    report_root = root / "publication" / "reports"
    json_path = report_root / "final_release_gate.json"
    atomic_write_bytes(json_path, canonical_json_bytes(gate.as_dict()))
    rows = "\n".join(
        f"| {item.check_id} | {item.task_number} | {item.status} | {item.message} |"
        for item in gate.checks
    )
    markdown = f"""# Final Release Gate

- Study ID: `{gate.study_id}`
- Eligible: `{str(gate.eligible).lower()}`
- Gate SHA-256: `{gate.gate_sha256}`

| Check | Task | Status | Result |
| --- | ---: | --- | --- |
{rows}

The gate distinguishes represented `N`, materialized `n`, and separately evidenced downstream replay `q`. It does not establish legal compliance, physical deletion, or operational HTGL capacity.
"""
    markdown_path = report_root / "final_release_gate.md"
    atomic_write_bytes(markdown_path, markdown.encode("utf-8"))
    return (
        ("publication/reports/final_release_gate.json", "public", True),
        ("publication/reports/final_release_gate.md", "public", True),
    )


def _assert_report_claim_discipline(text: str) -> None:
    lowered = text.lower()
    prohibited = (
        "450m users",
        "users executed",
        "physical deletion proved",
        "legally compliant",
        "represented population was executed",
    )
    hits = [item for item in prohibited if item in lowered]
    if hits:
        raise StudyPackageError(f"report contains prohibited scale/proof claims {hits}")
    if not all(token in text for token in ("`N`", "`n`", "`q`")):
        raise StudyPackageError("study report must define N, n, and q")


def _factor_registry_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.factor-registry.v1", "public", [
        ("registry_id", pa.string(), False), ("registry_version", pa.string(), False),
        ("registry_sha256", pa.string(), False), ("axis_id", pa.string(), False),
        ("execution_mode", pa.string(), False), ("level_id", pa.string(), False),
        ("value_json", pa.string(), False), ("claim_eligible", pa.bool_(), False),
        ("required_capability", pa.string(), True), ("scale_semantics", pa.string(), False),
    ])


def _condition_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.condition.v1", "public", [
        ("study_id", pa.string(), False), ("condition_id", pa.string(), False),
        ("ordinal", pa.int32(), False), ("design_mode", pa.string(), False),
        ("represented_population_N", pa.int64(), False), ("materialized_row_target_n", pa.int64(), False),
        ("executed_operation_target_q", pa.int64(), True), ("repetitions", pa.int32(), False),
        ("common_random_group", pa.string(), False), ("estimator_eligible", pa.bool_(), False),
        ("feasibility_status", pa.string(), False), ("feasibility_reasons_json", pa.string(), False),
        ("factor_level_ids_json", pa.string(), False), ("factor_values_json", pa.string(), False),
        ("projected_materialized_rows", pa.int64(), False),
        ("projected_stored_bytes_upper_bound", pa.int64(), False),
    ])


def _replicate_evidence_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.replicate-evidence.v1", "restricted", [
        ("condition_id", pa.string(), False), ("run_id", pa.string(), False),
        ("scenario_id", pa.string(), False), ("replicate_id", pa.int32(), False),
        ("execution_status", pa.string(), False), ("represented_population_N", pa.int64(), False),
        ("materialized_row_target_n", pa.int64(), False),
        ("materialized_governance_event_rows_n", pa.int64(), True),
        ("materialized_total_table_rows", pa.int64(), True), ("executed_operations_q", pa.int64(), True),
        ("seed_stream_digest", pa.string(), True), ("canonical_table_digest", pa.string(), True),
        ("retained_metric_count", pa.int64(), False), ("validation_status", pa.string(), False),
        ("known_total_status", pa.string(), False),
        ("maximum_absolute_relative_bias", pa.float64(), True), ("relative_rmse", pa.float64(), True),
        ("minimum_ci_coverage", pa.float64(), True), ("resource_status", pa.string(), False),
        ("generated_rows", pa.int64(), True), ("elapsed_seconds", pa.float64(), True),
        ("rows_per_second", pa.float64(), True), ("peak_resident_memory_bytes", pa.int64(), True),
        ("stored_bytes", pa.int64(), True), ("artifact_manifest_sha256", pa.string(), True),
        ("clean_rerun_digest_match", pa.bool_(), True), ("failure_code", pa.string(), True),
        ("failure_message", pa.string(), True),
    ])


def _metric_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.run-metric.v1", "public", [
        ("condition_id", pa.string(), False), ("evidence_phase", pa.string(), False),
        ("metric_id", pa.string(), False), ("run_id", pa.string(), False),
        ("scenario_id", pa.string(), False), ("replicate_id", pa.int32(), False),
        ("metric_domain", pa.string(), False), ("metric_name", pa.string(), False),
        ("value", pa.float64(), False), ("unit", pa.string(), False),
        ("standard_error", pa.float64(), True), ("ci_lower", pa.float64(), True),
        ("ci_upper", pa.float64(), True), ("estimator", pa.string(), False),
        ("weighting", pa.string(), False), ("baseline_id", pa.string(), True),
    ])


def _validation_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.validation-issue.v1", "restricted", [
        ("condition_id", pa.string(), False), ("scenario_id", pa.string(), False),
        ("replicate_id", pa.int32(), False), ("evidence_phase", pa.string(), False),
        ("check_id", pa.string(), False), ("run_id", pa.string(), False),
        ("severity", pa.string(), False), ("domain", pa.string(), False),
        ("status", pa.string(), False), ("observed_value", pa.string(), True),
        ("expected_condition", pa.string(), False), ("affected_record_ids", pa.list_(pa.string()), False),
        ("message", pa.string(), False), ("validator_version", pa.string(), False),
    ])


def _factor_metric_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.factor-metric.v1", "public", [
        ("factor_metric_id", pa.string(), False), ("condition_id", pa.string(), False),
        ("run_id", pa.string(), False), ("scenario_id", pa.string(), False),
        ("replicate_id", pa.int32(), False), ("axis_id", pa.string(), False),
        ("level_id", pa.string(), False), ("metric_name", pa.string(), False),
        ("value", pa.float64(), False), ("unit", pa.string(), False),
        ("numerator", pa.float64(), True), ("denominator", pa.float64(), True),
        ("estimator", pa.string(), False), ("weighting", pa.string(), False),
        ("claim_eligible", pa.bool_(), False), ("uncertainty_status", pa.string(), False),
        ("scope_json", pa.string(), False), ("represented_population_N", pa.int64(), False),
        ("materialized_row_target_n", pa.int64(), False),
        ("executed_operation_target_q", pa.int64(), True),
    ])


def _aggregate_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.metric-aggregate.v1", "public", [
        ("condition_id", pa.string(), False), ("aggregate_kind", pa.string(), False),
        ("represented_population_N", pa.int64(), False), ("materialized_row_target_n", pa.int64(), False),
        ("executed_operation_target_q", pa.int64(), True), ("aggregate_id", pa.string(), False),
        ("axis_id", pa.string(), True), ("level_id", pa.string(), True),
        ("metric_name", pa.string(), False), ("metric_key", pa.string(), False),
        ("metric_domain", pa.string(), False), ("scope_id", pa.string(), False),
        ("baseline_id", pa.string(), True), ("unit", pa.string(), False),
        ("estimator", pa.string(), False), ("weighting", pa.string(), False),
        ("replicate_ids", pa.list_(pa.int32()), False), ("replicate_count", pa.int32(), False),
        ("mean_value", pa.float64(), False), ("empirical_standard_error", pa.float64(), True),
        ("ci_lower", pa.float64(), True), ("ci_upper", pa.float64(), True),
        ("confidence_level", pa.float64(), False), ("uncertainty_method", pa.string(), False),
        ("uncertainty_status", pa.string(), False), ("uncertainty_reason", pa.string(), False),
        ("claim_eligible", pa.bool_(), True),
    ])


def _claim_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.scale-claim.v1", "public", [
        ("claim_id", pa.string(), False), ("condition_id", pa.string(), False),
        ("claim_class", pa.string(), False), ("represented_population_N", pa.int64(), False),
        ("materialized_row_target_n", pa.int64(), False), ("materialized_rows_min_n", pa.int64(), True),
        ("materialized_rows_max_n", pa.int64(), True), ("executed_operations_sum_q", pa.int64(), True),
        ("retained_repetitions", pa.int32(), False), ("required_repetitions", pa.int32(), False),
        ("validation_gate", pa.string(), False), ("statistical_gate", pa.string(), False),
        ("artifact_gate", pa.string(), False), ("reproducibility_gate", pa.string(), False),
        ("claim_status", pa.string(), False), ("claim_statement", pa.string(), False),
        ("prohibited_interpretation", pa.string(), False),
    ])


def _artifact_manifest_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(pa, "htgl.study.artifact-manifest.v1", "public", [
        ("relative_path", pa.string(), False), ("media_type", pa.string(), False),
        ("schema_id", pa.string(), True), ("schema_fingerprint", pa.string(), True),
        ("record_count", pa.int64(), True), ("stored_bytes", pa.int64(), False),
        ("sha256", pa.string(), False), ("privacy_class", pa.string(), False),
        ("publication_eligible", pa.bool_(), False),
    ])


def _normalize_aggregate_row(item: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(item)
    metric_key = str(row.get("metric_key", row.get("metric_name", "")))
    if not metric_key:
        raise StudyPackageError("metric aggregate lacks metric key/name")
    return {
        "condition_id": row["condition_id"],
        "aggregate_kind": row["aggregate_kind"],
        "represented_population_N": row["represented_population_N"],
        "materialized_row_target_n": row["materialized_row_target_n"],
        "executed_operation_target_q": row.get("executed_operation_target_q"),
        "aggregate_id": row["aggregate_id"],
        "axis_id": row.get("axis_id"),
        "level_id": row.get("level_id"),
        "metric_name": str(row.get("metric_name", metric_key)),
        "metric_key": metric_key,
        "metric_domain": row["metric_domain"],
        "scope_id": row["scope_id"],
        "baseline_id": row.get("baseline_id"),
        "unit": row["unit"],
        "estimator": row["estimator"],
        "weighting": row["weighting"],
        "replicate_ids": list(row["replicate_ids"]),
        "replicate_count": row["replicate_count"],
        "mean_value": row["mean_value"],
        "empirical_standard_error": row.get("empirical_standard_error"),
        "ci_lower": row.get("ci_lower"),
        "ci_upper": row.get("ci_upper"),
        "confidence_level": row["confidence_level"],
        "uncertainty_method": row["uncertainty_method"],
        "uncertainty_status": row["uncertainty_status"],
        "uncertainty_reason": row["uncertainty_reason"],
        "claim_eligible": row.get("claim_eligible"),
    }


def _schema(pa: Any, schema_id: str, privacy: str, fields: Sequence[tuple[str, Any, bool]]) -> Any:
    fingerprint = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_id": schema_id,
                "fields": [(name, str(dtype), nullable) for name, dtype, nullable in fields],
            }
        )
    ).hexdigest()
    metadata = {
        b"schema_id": schema_id.encode("ascii"),
        b"schema_fingerprint": fingerprint.encode("ascii"),
        b"privacy_class": privacy.encode("ascii"),
        b"authoritative_storage": b"parquet_zstd",
        b"schema_version": b"1.0.0",
    }
    return pa.schema(
        [pa.field(name, dtype, nullable=nullable) for name, dtype, nullable in fields],
        metadata=metadata,
    )


def _write_parquet(path: Path, schema: Any, rows: Sequence[Mapping[str, Any]], level: int) -> None:
    pa, pq = _require_pyarrow()
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist([dict(row) for row in rows], schema=schema)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        pq.write_table(
            table,
            temporary,
            compression="zstd",
            compression_level=level,
            use_dictionary=False,
            write_statistics=True,
            version="2.6",
            data_page_version="2.0",
        )
        with temporary.open("rb+") as handle:
            os.fsync(handle.fileno())
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _inventory_row(
    root: Path,
    path: Path,
    *,
    schema_id: str | None,
    schema_fingerprint: str | None,
    record_count: int | None,
    privacy_class: str,
    publication_eligible: bool,
) -> dict[str, Any]:
    payload = path.read_bytes()
    suffix = path.suffix.lower()
    media_type = {
        ".parquet": "application/vnd.apache.parquet",
        ".csv": "text/csv",
        ".md": "text/markdown",
        ".json": "application/json",
    }.get(suffix, "application/octet-stream")
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "media_type": media_type,
        "schema_id": schema_id,
        "schema_fingerprint": schema_fingerprint,
        "record_count": record_count,
        "stored_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "privacy_class": privacy_class,
        "publication_eligible": publication_eligible,
    }


def _schema_id(schema: Any) -> str:
    return (schema.metadata or {})[b"schema_id"].decode("ascii")


def _schema_fingerprint(schema: Any) -> str:
    return (schema.metadata or {})[b"schema_fingerprint"].decode("ascii")


def _require_pyarrow() -> tuple[Any, Any]:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise StudyPackageError("pyarrow is required for authoritative study artifacts") from exc
    return pa, pq


def _checkpoint(options: StudyPackageOptions, phase: str, root: Path) -> None:
    if options.failure_injector is not None:
        options.failure_injector(phase, root)
