"""Unified production CLI for claim-aware HTGL dataset workflows."""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.api import (
    AdapterExportResult,
    ClaimReportResult,
    CompilationWorkflowResult,
    ReproductionWorkflowResult,
    ResolvedConfigResult,
    StageExecutionResult,
    StudyWorkflowResult,
    WorkflowApiError,
    WorkflowEvent,
    compile_artifact_release,
    compute_metrics,
    explain_config_path,
    explain_study_plan,
    export_adapter,
    generate_dataset,
    report_claims,
    reproduce_release,
    resolve_config_contract,
    run_final_release_gate,
    run_factorial_study,
    validate_dataset,
)
from htgl_dataset_generator.artifacts import ArtifactCompilerError
from htgl_dataset_generator.config import ConfigResolutionError
from htgl_dataset_generator.experiments import (
    DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    DEFAULT_MEMORY_BUDGET_BYTES,
    PrecisionJustification,
)


COLLISION_POLICIES = ("fail", "reuse_identical", "replace_owned")
SOURCE_LABELS = (
    "controlled_synthetic",
    "calibrated_from_source",
    "imported_template",
    "publication_derived",
    "deployment_measured",
)


class StructuredEventWriter:
    """Write stable structured workflow events without semantic wall-clock fields."""

    def __init__(self, stream: Any, log_format: str) -> None:
        self._stream = stream
        self._format = log_format

    def __call__(self, event: WorkflowEvent) -> None:
        payload = _jsonable(asdict(event))
        if self._format == "json":
            print(_compact_json(payload), file=self._stream, flush=True)
            return
        details = payload.pop("details", None)
        resource_usage = payload.pop("resource_usage", None)
        fields = " ".join(
            f"{key}={json.dumps(value, sort_keys=True)}"
            for key, value in payload.items()
            if value is not None
        )
        suffix = ""
        if resource_usage is not None:
            suffix += f" resources={_compact_json(resource_usage)}"
        if details is not None:
            suffix += f" details={_compact_json(details)}"
        print(fields + suffix, file=self._stream, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one production workflow and return a stable process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    logger = StructuredEventWriter(sys.stderr, args.log_format)
    try:
        if args.dry_run or args.explain:
            if args.command in {"run-study", "release-gate"}:
                explanation = explain_study_plan(
                    args.config,
                    study_id=args.study_id,
                    design_mode=args.design,
                    repetitions=args.repetitions,
                    precision_justification=_precision_justification(args),
                    maximum_conditions=args.maximum_conditions,
                    maximum_replicates=args.maximum_replicates,
                    maximum_rows_per_replicate=args.maximum_rows_per_replicate,
                    maximum_total_rows=args.maximum_total_rows,
                    enable_10m_materialization=args.enable_10m_materialization,
                    workflow_command=args.command,
                )
            else:
                explanation = explain_config_path(args.config, args.command)
            explanation = {
                **explanation,
                "execution_mode": "dry_run" if args.dry_run else "explain",
                "writes_performed": False,
                "output_directory": str(args.output_dir.resolve()),
            }
            print(_compact_json(explanation))
            return 0
        result = _dispatch(args, logger)
        print(_compact_json(_result_summary(result)))
        return 0
    except (ConfigResolutionError, WorkflowApiError, ArtifactCompilerError) as exc:
        _write_error(args, exc, logger, exit_code=20)
        return 20
    except (OSError, ValueError) as exc:
        _write_error(args, exc, logger, exit_code=30)
        return 30
    except Exception as exc:
        if args.debug:
            raise
        _write_error(args, exc, logger, exit_code=70)
        return 70


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="htgl-dataset",
        description=(
            "Generate and validate governance benchmark artifacts. N is represented "
            "population, n is materialized rows, and q is separately replayed operations."
        ),
    )
    parser.add_argument("--version", action="version", version=_package_version())
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    resolve = subparsers.add_parser(
        "resolve-config", help="resolve and persist the immutable S00 contract"
    )
    _add_common(resolve)
    _add_collision(resolve, default="reuse_identical")

    generate = subparsers.add_parser(
        "generate", help="run S00-S12 and write Parquet/ZSTD command artifacts"
    )
    _add_common(generate)
    _add_workers(generate)
    _add_checkpointing(generate)
    _add_collision(generate, default="reuse_identical")

    validate = subparsers.add_parser(
        "validate", help="run the complete fail-closed S13 validation registry"
    )
    _add_common(validate)
    _add_workers(validate)
    _add_checkpointing(validate)
    _add_collision(validate, default="reuse_identical")

    metrics = subparsers.add_parser(
        "metrics", help="run S14 metrics, provenance, uncertainty, and comparisons"
    )
    _add_common(metrics)
    _add_workers(metrics)
    _add_checkpointing(metrics)
    _add_collision(metrics, default="reuse_identical")

    compile_parser = subparsers.add_parser(
        "compile-artifacts",
        help="run all release gates and atomically publish an S15 release",
    )
    _add_common(compile_parser)
    _add_workers(compile_parser)
    _add_collision(compile_parser, default="fail")
    compile_parser.add_argument(
        "--publication",
        action="store_true",
        help="acknowledge that all mandatory publication gates must execute and pass",
    )

    study = subparsers.add_parser(
        "run-study", help="plan or execute the controlled P8 factorial study"
    )
    _add_common(study)
    _add_workers(study)
    _add_collision(study, default="fail")
    study.add_argument("--study-id", required=True)
    study.add_argument(
        "--design",
        choices=("pairwise_covering", "full_factorial"),
        default="pairwise_covering",
    )
    study.add_argument("--repetitions", type=int, default=30)
    study.add_argument("--condition-id", action="append", default=[])
    study.add_argument("--publication", action="store_true")
    study.add_argument("--maximum-conditions", type=int, default=512)
    study.add_argument("--maximum-replicates", type=int, default=15_360)
    study.add_argument("--maximum-rows-per-replicate", type=int, default=1_000_000)
    study.add_argument("--maximum-total-rows", type=int, default=2_000_000_000)
    study.add_argument("--enable-10m-materialization", action="store_true")
    study.add_argument("--precision-half-width", type=float)
    study.add_argument("--precision-confidence", type=float, default=0.95)
    study.add_argument("--pilot-standard-deviation", type=float)
    study.add_argument("--pilot-repetitions", type=int)
    study.add_argument("--precision-source-label", choices=SOURCE_LABELS)
    study.add_argument("--precision-source-id")

    release_gate = subparsers.add_parser(
        "release-gate",
        help="execute the exact declared study and publish only after every final gate passes",
    )
    _add_common(release_gate)
    _add_workers(release_gate)
    _add_collision(release_gate, default="fail")
    release_gate.add_argument("--study-id", required=True)
    release_gate.add_argument(
        "--design",
        choices=("pairwise_covering", "full_factorial"),
        default="pairwise_covering",
    )
    release_gate.add_argument("--repetitions", type=int, default=30)
    release_gate.add_argument("--condition-id", action="append", default=[])
    release_gate.add_argument("--maximum-conditions", type=int, default=512)
    release_gate.add_argument("--maximum-replicates", type=int, default=15_360)
    release_gate.add_argument("--maximum-rows-per-replicate", type=int, default=1_000_000)
    release_gate.add_argument("--maximum-total-rows", type=int, default=2_000_000_000)
    release_gate.add_argument("--enable-10m-materialization", action="store_true")
    release_gate.add_argument("--precision-half-width", type=float)
    release_gate.add_argument("--precision-confidence", type=float, default=0.95)
    release_gate.add_argument("--pilot-standard-deviation", type=float)
    release_gate.add_argument("--pilot-repetitions", type=int)
    release_gate.add_argument("--precision-source-label", choices=SOURCE_LABELS)
    release_gate.add_argument("--precision-source-id")

    reproduce = subparsers.add_parser(
        "reproduce", help="cleanly rerun and compare an immutable S15 release"
    )
    _add_common(reproduce)
    _add_workers(reproduce)
    _add_collision(reproduce, default="fail")
    reproduce.add_argument("--source-release", type=Path, required=True)

    adapter = subparsers.add_parser(
        "export-adapter", help="export one verified projection from canonical truth"
    )
    _add_common(adapter)
    _add_collision(adapter, default="reuse_identical")
    adapter.add_argument("--source-release", type=Path, required=True)
    adapter.add_argument("--adapter-id", required=True)
    adapter.add_argument(
        "--access-class", choices=("public", "restricted"), default="public"
    )

    claims = subparsers.add_parser(
        "report-claims", help="verify and filter the immutable Appendix-D claim matrix"
    )
    _add_common(claims)
    _add_collision(claims, default="reuse_identical")
    claims.add_argument("--source-release", type=Path, required=True)
    claims.add_argument(
        "--status",
        action="append",
        choices=("supported", "not_supported", "diagnostic_only"),
        dest="statuses",
    )
    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve and explain without generation or filesystem writes",
    )
    mode.add_argument(
        "--explain",
        action="store_true",
        help="explain stages and scientific claim eligibility without writes",
    )
    parser.add_argument("--log-format", choices=("json", "text"), default="json")
    parser.add_argument("--debug", action="store_true")


def _add_workers(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-in-flight", type=int)
    parser.add_argument(
        "--memory-budget-bytes",
        type=int,
        default=DEFAULT_MEMORY_BUDGET_BYTES,
    )
    parser.add_argument(
        "--estimated-bytes-per-materialized-row",
        type=int,
        default=DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    )


def _add_checkpointing(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="verify and reuse every compatible generator-owned checkpoint",
    )


def _add_collision(parser: argparse.ArgumentParser, *, default: str) -> None:
    parser.add_argument(
        "--collision-policy", choices=COLLISION_POLICIES, default=default
    )


def _dispatch(args: argparse.Namespace, logger: StructuredEventWriter) -> Any:
    common = {
        "config_path": args.config,
        "output_dir": args.output_dir,
        "event_sink": logger,
    }
    if args.command == "resolve-config":
        return resolve_config_contract(
            **common,
            collision_policy=args.collision_policy,
        )
    if args.command == "generate":
        return generate_dataset(
            **common,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            checkpoint_dir=args.checkpoint_dir,
            resume=args.resume,
            collision_policy=args.collision_policy,
        )
    if args.command == "validate":
        return validate_dataset(
            **common,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            checkpoint_dir=args.checkpoint_dir,
            resume=args.resume,
            collision_policy=args.collision_policy,
        )
    if args.command == "metrics":
        return compute_metrics(
            **common,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            checkpoint_dir=args.checkpoint_dir,
            resume=args.resume,
            collision_policy=args.collision_policy,
        )
    if args.command == "compile-artifacts":
        return compile_artifact_release(
            **common,
            publication=args.publication,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            collision_policy=args.collision_policy,
        )
    if args.command == "run-study":
        return run_factorial_study(
            **common,
            study_id=args.study_id,
            design_mode=args.design,
            repetitions=args.repetitions,
            condition_ids=args.condition_id,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            publication=args.publication,
            precision_justification=_precision_justification(args),
            maximum_conditions=args.maximum_conditions,
            maximum_replicates=args.maximum_replicates,
            maximum_rows_per_replicate=args.maximum_rows_per_replicate,
            maximum_total_rows=args.maximum_total_rows,
            enable_10m_materialization=args.enable_10m_materialization,
            collision_policy=args.collision_policy,
        )
    if args.command == "release-gate":
        return run_final_release_gate(
            **common,
            study_id=args.study_id,
            design_mode=args.design,
            repetitions=args.repetitions,
            condition_ids=args.condition_id,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            precision_justification=_precision_justification(args),
            maximum_conditions=args.maximum_conditions,
            maximum_replicates=args.maximum_replicates,
            maximum_rows_per_replicate=args.maximum_rows_per_replicate,
            maximum_total_rows=args.maximum_total_rows,
            enable_10m_materialization=args.enable_10m_materialization,
            collision_policy=args.collision_policy,
        )
    if args.command == "reproduce":
        return reproduce_release(
            **common,
            source_release=args.source_release,
            worker_count=args.workers,
            max_in_flight=args.max_in_flight,
            memory_budget_bytes=args.memory_budget_bytes,
            estimated_bytes_per_materialized_row=args.estimated_bytes_per_materialized_row,
            collision_policy=args.collision_policy,
        )
    if args.command == "export-adapter":
        return export_adapter(
            **common,
            source_release=args.source_release,
            adapter_id=args.adapter_id,
            access_class=args.access_class,
            collision_policy=args.collision_policy,
        )
    if args.command == "report-claims":
        kwargs: dict[str, Any] = {
            **common,
            "source_release": args.source_release,
            "collision_policy": args.collision_policy,
        }
        if args.statuses:
            kwargs["statuses"] = args.statuses
        return report_claims(**kwargs)
    raise WorkflowApiError(f"unsupported command {args.command!r}")


def _precision_justification(args: argparse.Namespace) -> PrecisionJustification | None:
    values = (
        args.precision_half_width,
        args.pilot_standard_deviation,
        args.pilot_repetitions,
        args.precision_source_label,
        args.precision_source_id,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ConfigResolutionError(
            "precision override requires half-width, pilot standard deviation, pilot "
            "repetitions, source label, and pinned source ID"
        )
    return PrecisionJustification(
        method="normal_half_width_v1",
        confidence_level=args.precision_confidence,
        target_half_width=args.precision_half_width,
        pilot_standard_deviation=args.pilot_standard_deviation,
        pilot_repetitions=args.pilot_repetitions,
        source_label=args.precision_source_label,
        source_id=args.precision_source_id,
    )


def _result_summary(result: Any) -> Mapping[str, Any]:
    if isinstance(result, ResolvedConfigResult):
        return {
            "command": "resolve-config",
            "run_id": result.resolved.run.run_id,
            "config_sha256": result.resolved.config_sha256,
            "output_path": result.output_path,
            "represented_population_N": result.explanation["represented_population_N"],
            "materialized_row_target_n": result.explanation["materialized_row_target_n"],
            "executed_operation_target_not_observed_q": result.explanation[
                "executed_operation_target_not_observed_q"
            ],
        }
    if isinstance(result, StageExecutionResult):
        return _jsonable(asdict(result))
    if isinstance(result, CompilationWorkflowResult):
        return {
            "command": "compile-artifacts",
            "publication_eligible": result.publication_eligible,
            "release_root": result.release.release_root,
            "release_bundles": {
                access: bundle.release_root
                for access, bundle in sorted(result.release.bundles.items())
            },
            "manifest_sha256": result.release.manifest_sha256,
            "release_semantic_digest": result.release.semantic_digest,
            "release_byte_digest": result.release.byte_digest,
            "resource_usage": result.resource_usage,
        }
    if isinstance(result, ReproductionWorkflowResult):
        return _jsonable(asdict(result))
    if isinstance(result, AdapterExportResult):
        return _jsonable(asdict(result))
    if isinstance(result, ClaimReportResult):
        return _jsonable(asdict(result))
    if isinstance(result, StudyWorkflowResult):
        return _jsonable(asdict(result))
    if is_dataclass(result):
        return _jsonable(asdict(result))
    raise TypeError(f"unsupported workflow result type {type(result).__name__}")


def _write_error(
    args: argparse.Namespace,
    exc: Exception,
    logger: StructuredEventWriter,
    *,
    exit_code: int,
) -> None:
    event = WorkflowEvent(
        sequence=0,
        level="error",
        run_id="unresolved",
        scenario_id="unresolved",
        replicate_id=None,
        stage="CLI",
        component=args.command or "argument_parser",
        event="command_failed",
        status="failed",
        deterministic_status="deterministic_error",
        details={
            "error_type": type(exc).__name__,
            "message": str(exc),
            "exit_code": exit_code,
        },
    )
    logger(event)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _compact_json(value: Any) -> str:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _package_version() -> str:
    try:
        return version("gridweave")
    except PackageNotFoundError:
        return "GridWeave (editable source; legacy interface)"


if __name__ == "__main__":
    raise SystemExit(main())
