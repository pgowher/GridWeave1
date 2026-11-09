"""CLI for planning and diagnostic execution of the P8 factorial study."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
from typing import Sequence

from htgl_dataset_generator.config import resolve_config_file
from htgl_dataset_generator.experiments import (
    PrecisionJustification,
    StudyPackageOptions,
    build_factorial_study_plan,
    compile_study_evidence_package,
    default_study_resource_budget,
    execute_factorial_study,
    planned_study_execution,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    base = resolve_config_file(args.config)
    budget = default_study_resource_budget()
    capabilities = set(budget.capabilities)
    maximum_rows = args.maximum_rows_per_replicate
    if args.enable_10m_materialization:
        capabilities.add("materialize_1e7_rows")
        maximum_rows = max(maximum_rows, 10_000_000)
    budget = replace(
        budget,
        maximum_conditions=args.maximum_conditions,
        maximum_replicates=args.maximum_replicates,
        maximum_materialized_rows_per_replicate=maximum_rows,
        maximum_total_materialized_rows=args.maximum_total_rows,
        capabilities=frozenset(capabilities),
    )
    precision = _precision(args)
    plan = build_factorial_study_plan(
        args.study_id,
        design_mode=args.design,
        requested_repetitions=args.repetitions,
        precision_justification=precision,
        resource_budget=budget,
    )
    if args.execute_condition:
        build = execute_factorial_study(
            base,
            plan,
            condition_ids=args.execute_condition,
            worker_count=args.workers,
        )
    else:
        build = planned_study_execution(base, plan)
    result = compile_study_evidence_package(
        build,
        args.output,
        options=StudyPackageOptions(
            package_kind="diagnostic",
            collision_policy=args.collision_policy,
        ),
    )
    print(
        json.dumps(
            {
                "study_id": plan.study_id,
                "design_mode": plan.design_mode,
                "raw_full_factorial_conditions": plan.full_factorial_condition_count,
                "selected_design_conditions": plan.selected_condition_count,
                "eligible_conditions": sum(
                    item.feasibility_status == "eligible" for item in plan.conditions
                ),
                "represented_population_symbol": "N",
                "materialized_rows_symbol": "n",
                "executed_operations_symbol": "q",
                "publication_eligible": build.publication_eligible,
                "publication_blockers": build.publication_blockers,
                "package_root": str(result.package_root),
                "manifest_sha256": result.manifest_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _precision(args: argparse.Namespace) -> PrecisionJustification | None:
    values = (
        args.precision_half_width,
        args.pilot_standard_deviation,
        args.pilot_repetitions,
        args.precision_source_id,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise SystemExit(
            "precision override requires --precision-half-width, --pilot-standard-deviation, "
            "--pilot-repetitions, and --precision-source-id"
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="htgl-factorial-study",
        description=(
            "Plan or diagnostically execute the controlling HTGL factor study. "
            "N is represented population, n is materialized rows, and q requires separate replay evidence."
        ),
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--study-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--design", choices=("pairwise_covering", "full_factorial"), default="pairwise_covering")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--execute-condition", action="append", default=[])
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--maximum-conditions", type=int, default=512)
    parser.add_argument("--maximum-replicates", type=int, default=15_360)
    parser.add_argument("--maximum-rows-per-replicate", type=int, default=1_000_000)
    parser.add_argument("--maximum-total-rows", type=int, default=2_000_000_000)
    parser.add_argument("--enable-10m-materialization", action="store_true")
    parser.add_argument("--collision-policy", choices=("fail", "reuse_identical", "replace_owned"), default="fail")
    parser.add_argument("--precision-half-width", type=float)
    parser.add_argument("--precision-confidence", type=float, default=0.95)
    parser.add_argument("--pilot-standard-deviation", type=float)
    parser.add_argument("--pilot-repetitions", type=int)
    parser.add_argument(
        "--precision-source-label",
        choices=(
            "controlled_synthetic",
            "calibrated_from_source",
            "imported_template",
            "publication_derived",
            "deployment_measured",
        ),
        default="controlled_synthetic",
    )
    parser.add_argument("--precision-source-id")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
