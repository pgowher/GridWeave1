"""Independent, fail-closed final publication release gate.

The gate consumes retained study evidence and immutable S15 condition releases.
It never treats a configured target, an in-memory success flag, or a represented
population as execution evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.artifacts.canonical import domain_sha256
from htgl_dataset_generator.artifacts.manifest import verify_manifest_closure
from htgl_dataset_generator.config import CORE_VALIDATION_CHECK_IDS
from htgl_dataset_generator.schemas import load_contract

from .study_models import FactorialStudyPlan, StudyExecutionBuild


FORBIDDEN_REPORT_PHRASES: tuple[str, ...] = (
    "htgl handled 450 million users",
    "900 million transactions executed",
    "proof of erasure",
    "gdpr compliant",
    "represented population was executed",
    "users executed",
    "physical deletion proved",
    "legally compliant",
    "novel algorithm",
    "we are the first",
    "this is the first",
)

REQUIRED_FINAL_REPORTS: tuple[str, ...] = (
    "claim_matrix.csv",
    "data_card.md",
    "license.md",
    "limitations.md",
    "model_card.md",
    "publication_items.json",
    "quality_report.json",
    "study_report.md",
    "threat_model.md",
)


class FinalReleaseGateError(RuntimeError):
    """Raised with stable diagnostics when final publication is ineligible."""

    def __init__(self, checks: Sequence["FinalReleaseCheck"]) -> None:
        self.checks = tuple(checks)
        failures = tuple(item for item in self.checks if item.status != "pass")
        detail = "; ".join(
            (
                f"{item.check_id}: {item.message} "
                f"(observed={item.observed}; expected={item.expected}; "
                f"affected={list(item.affected_ids[:8])})"
            )
            for item in failures
        )
        super().__init__(f"final release gate failed ({len(failures)} checks): {detail}")


@dataclass(frozen=True)
class FinalReleaseCheck:
    check_id: str
    task_number: int
    status: str
    observed: str
    expected: str
    message: str
    affected_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class FinalReleaseGateResult:
    study_id: str
    checks: tuple[FinalReleaseCheck, ...]
    eligible: bool
    gate_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": "htgl.final-release-gate.v1",
            "study_id": self.study_id,
            "eligible": self.eligible,
            "gate_sha256": self.gate_sha256,
            "checks": [asdict(item) for item in self.checks],
        }


def require_complete_publication_selection(
    plan: FactorialStudyPlan,
    condition_ids: Iterable[str],
) -> tuple[str, ...]:
    """Require the exact eligible condition set before expensive execution starts."""

    selected = tuple(condition_ids)
    expected = tuple(
        item.condition_id
        for item in plan.conditions
        if item.feasibility_status == "eligible"
    )
    failures: list[FinalReleaseCheck] = []
    if len(selected) != len(set(selected)):
        failures.append(
            _failure(
                "FINAL-SELECTION-001", 1, str(len(selected)), "unique condition IDs",
                "selected publication condition IDs contain duplicates",
            )
        )
    missing = sorted(set(expected) - set(selected))
    extra = sorted(set(selected) - set(expected))
    if missing or extra:
        failures.append(
            _failure(
                "FINAL-SELECTION-002", 1,
                f"selected={len(set(selected))}; missing={len(missing)}; extra={len(extra)}",
                f"exact eligible design set of {len(expected)} conditions",
                "publication selection does not equal the eligible study design",
                (*missing[:16], *extra[:16]),
            )
        )
    blocked = tuple(
        item for item in plan.conditions if item.feasibility_status == "blocked"
    )
    if blocked:
        details = tuple(
            f"{item.condition_id}:{','.join(item.feasibility_reasons)}"
            for item in blocked[:16]
        )
        failures.append(
            _failure(
                "FINAL-FEASIBILITY-001", 1, f"blocked={len(blocked)}", "blocked=0",
                "the declared study design contains resource or capability blocked conditions",
                details,
            )
        )
    if plan.pairwise_covered_count != plan.pairwise_requirement_count:
        failures.append(
            _failure(
                "FINAL-DESIGN-001", 1,
                f"{plan.pairwise_covered_count}/{plan.pairwise_requirement_count}",
                "complete declared factor-pair coverage",
                "factor-pair coverage is incomplete",
            )
        )
    if failures:
        raise FinalReleaseGateError(failures)
    return expected


def evaluate_final_release_build(
    build: StudyExecutionBuild,
    condition_release_root: str | Path,
) -> FinalReleaseGateResult:
    """Recompute Tasks 1-11 from retained evidence and final S15 bytes."""

    checks: list[FinalReleaseCheck] = []
    plan = build.plan
    eligible_conditions = tuple(
        item for item in plan.conditions if item.feasibility_status == "eligible"
    )
    expected_keys = {
        (item.condition_id, replicate_id)
        for item in eligible_conditions
        for replicate_id in range(item.repetitions)
    }
    executed_rows = tuple(
        row for row in build.replicate_evidence if row.execution_status == "executed"
    )
    executed_keys = {(row.condition_id, row.replicate_id) for row in executed_rows}
    missing_keys = sorted(expected_keys - executed_keys)
    extra_keys = sorted(executed_keys - expected_keys)
    checks.append(
        _check(
            "FINAL-EXECUTION-001", 1,
            not missing_keys and not extra_keys,
            f"executed={len(executed_keys)}; expected={len(expected_keys)}",
            "one executed ledger row for every eligible condition and declared replicate",
            "all selected study cells executed" if not missing_keys and not extra_keys
            else "study execution ledger is incomplete or contains out-of-design executions",
            (*_key_strings(missing_keys[:8]), *_key_strings(extra_keys[:8])),
        )
    )

    repetition_failures: list[str] = []
    for condition in eligible_conditions:
        observed = sorted(
            row.replicate_id
            for row in executed_rows
            if row.condition_id == condition.condition_id
        )
        expected = list(range(condition.repetitions))
        if observed != expected or len(observed) < plan.required_repetitions:
            repetition_failures.append(condition.condition_id)
    checks.append(
        _check(
            "FINAL-REPETITIONS-001", 2, not repetition_failures,
            f"conditions_with_incomplete_repetitions={len(repetition_failures)}",
            f"each eligible condition retains all declared repetitions and at least {plan.required_repetitions}",
            "declared independent repetitions are complete" if not repetition_failures
            else "one or more conditions omit declared repetitions",
            repetition_failures[:16],
        )
    )

    validation_index, validation_errors = _validation_index(build.validation_issues)
    missing_validation: list[str] = list(validation_errors)
    failing_validation: list[str] = []
    for condition_id, replicate_id in sorted(expected_keys):
        for check_id in CORE_VALIDATION_CHECK_IDS:
            key = (condition_id, replicate_id, check_id)
            row = validation_index.get(key)
            if row is None:
                missing_validation.append(f"{condition_id}/{replicate_id}/{check_id}")
                continue
            status = str(row.get("status"))
            if status == "not_applicable":
                if not str(row.get("message") or "").strip():
                    failing_validation.append(f"{condition_id}/{replicate_id}/{check_id}:unjustified_not_applicable")
            elif status != "pass":
                failing_validation.append(f"{condition_id}/{replicate_id}/{check_id}:{status}")
    checks.append(
        _check(
            "FINAL-VALIDATION-001", 3,
            not missing_validation and not failing_validation,
            f"missing={len(missing_validation)}; nonpassing={len(failing_validation)}",
            "every mandatory S13 check is retained and pass or justified not_applicable",
            "routine and anomaly certificates are complete" if not missing_validation and not failing_validation
            else "mandatory validation evidence is missing, not executed, failed, or unjustified",
            (*missing_validation[:8], *failing_validation[:8]),
        )
    )

    checks.extend(
        _domain_validation_checks(
            validation_index,
            expected_keys,
            (
                ("FINAL-REFERENCES-001", 4, ("FK-001", "RECONCILIATION-001", "MANIFEST-001"), "actor, catalog, event, policy, evidence, observer, sample, and manifest references reconcile"),
                ("FINAL-DAG-001", 5, ("DAG-001",), "causal DAG acyclicity, depth, and dependency closure recompute"),
                ("FINAL-ARRIVAL-001", 6, ("TEMPORAL-ARRIVAL-001",), "arrival-model statistical diagnostics pass"),
                ("FINAL-PRIVACY-001", 7, ("OBSERVER-001", "PRIVACY-001"), "public projections pass omission and leakage checks"),
                ("FINAL-EVIDENCE-001", 8, ("EVIDENCE-001",), "receipt labels satisfy the independent obligation oracle"),
                ("FINAL-SAMPLING-001", 9, ("SAMPLING-001", "N-N-Q-001"), "sampling probabilities, weights, eligibility, known-total recovery, and N/n/q semantics pass"),
            ),
        )
    )

    metric_names_by_key: dict[tuple[str, int], set[str]] = {}
    for row in build.run_metrics:
        key = (str(row["condition_id"]), int(row["replicate_id"]))
        metric_names_by_key.setdefault(key, set()).add(str(row["metric_name"]))
    required_metric_names = {
        "count_mean_ratio", "dispersion_index", "time_rescaling_ks", "bin_deviance",
        "transition_conformance_rate", "causal_orphan_rate", "golden_decision_accuracy",
        "target_violation_success", "collateral_violation_rate", "obligation_coverage",
        "sufficiency_precision_recall", "visible_event_coverage", "sealed_truth_leakage",
        "effective_sample_size", "relative_bias_known_total", "ci_coverage",
        "deterministic_digest_match", "manifest_coverage", "generation_rows_per_second",
        "peak_resident_memory_bytes",
    }
    metric_failures = [
        f"{condition_id}/{replicate_id}:{','.join(sorted(required_metric_names - metric_names_by_key.get((condition_id, replicate_id), set())))}"
        for condition_id, replicate_id in sorted(expected_keys)
        if required_metric_names - metric_names_by_key.get((condition_id, replicate_id), set())
    ]
    configured_arrival_modes = {
        str(item.factor_values["arrival_model"]) for item in eligible_conditions
    }
    required_arrival_modes = {
        str(level.value)
        for level in plan.registry.axis("arrival_model").levels
        if level.claim_eligible
    }
    mode_gap = sorted(required_arrival_modes - configured_arrival_modes)
    checks.append(
        _check(
            "FINAL-METRICS-001", 6,
            not metric_failures and not mode_gap and bool(build.metric_aggregates),
            f"metric_gaps={len(metric_failures)}; arrival_mode_gaps={len(mode_gap)}; aggregates={len(build.metric_aggregates)}",
            "mandatory per-replicate metrics, every claim-eligible arrival mode, and uncertainty aggregates",
            "statistical and semantic metric evidence is complete" if not metric_failures and not mode_gap and build.metric_aggregates
            else "mandatory metrics, model modes, or replicate uncertainty aggregates are incomplete",
            (*metric_failures[:8], *mode_gap[:8]),
        )
    )

    manifest_failures = _verify_condition_releases(
        Path(condition_release_root), executed_rows
    )
    checks.append(
        _check(
            "FINAL-IMMUTABLE-SOURCES-001", 10, not manifest_failures,
            f"condition_release_failures={len(manifest_failures)}",
            "every executed condition binds to one byte-verified immutable S15 release",
            "condition releases and report sources are immutable" if not manifest_failures
            else "condition release manifests or final bytes do not reconcile",
            manifest_failures[:16],
        )
    )

    reproducibility_failures = [
        f"{row.condition_id}/{row.replicate_id}"
        for row in executed_rows
        if row.clean_rerun_digest_match is not True
        or not row.canonical_table_digest
        or not row.seed_stream_digest
    ]
    checks.append(
        _check(
            "FINAL-REPRODUCIBILITY-001", 11, not reproducibility_failures,
            f"failures={len(reproducibility_failures)}",
            "every replicate retains seed, canonical digest, and clean-rerun equality",
            "clean rerun evidence reproduces declared semantic hashes" if not reproducibility_failures
            else "clean-rerun or deterministic identity evidence is incomplete",
            reproducibility_failures[:16],
        )
    )

    supported_450m = [
        claim for claim in build.scale_claims
        if claim.represented_population_N == 450_000_000
        and claim.claim_status == "supported_represented_scale"
    ]
    checks.append(
        _check(
            "FINAL-CLAIMS-001", 9,
            bool(supported_450m) and not build.publication_blockers and build.publication_eligible,
            f"supported_450m={len(supported_450m)}; blockers={len(build.publication_blockers)}",
            "a supported represented-scale claim with no publication blockers and no N/n/q conflation",
            "represented-scale claims are evidence-gated" if supported_450m and not build.publication_blockers and build.publication_eligible
            else "represented-scale claim evidence is incomplete",
            build.publication_blockers[:16],
        )
    )
    return _result(plan.study_id, checks, raise_on_failure=True)


def complete_staged_report_gate(
    preliminary: FinalReleaseGateResult,
    staging_root: Path,
) -> FinalReleaseGateResult:
    """Verify Tasks 10, 12, and 13 after deterministic reports are staged."""

    checks = list(preliminary.checks)
    report_root = staging_root / "publication" / "reports"
    missing = [name for name in REQUIRED_FINAL_REPORTS if not (report_root / name).is_file()]
    document_failures = list(missing)
    if not missing:
        for name in REQUIRED_FINAL_REPORTS:
            if not (report_root / name).read_bytes():
                document_failures.append(f"{name}:empty")
        license_text = (report_root / "license.md").read_text(encoding="utf-8")
        if "NO-LICENSE-GRANT" not in license_text and "SPDX-License-Identifier:" not in license_text:
            document_failures.append("license.md:missing explicit license status or SPDX identifier")
        try:
            quality = json.loads((report_root / "quality_report.json").read_text(encoding="utf-8"))
            if quality.get("format") != "htgl.factorial-study-quality-report.v1":
                document_failures.append("quality_report.json:unsupported format")
        except (OSError, json.JSONDecodeError) as exc:
            document_failures.append(f"quality_report.json:invalid JSON: {exc}")
        claim_lines = (report_root / "claim_matrix.csv").read_text(encoding="utf-8").splitlines()
        claim_fields = set(claim_lines[0].split(",")) if claim_lines else set()
        for field in ("claim_id", "evidence_class", "claim_text", "validation_gate", "claim_status"):
            if field not in claim_fields:
                document_failures.append(f"claim_matrix.csv:missing {field}")
    checks.append(
        _check(
            "FINAL-DOCUMENTS-001", 12, not document_failures,
            f"failures={len(document_failures)}", "all required publication documents with explicit contracts",
            "data card, model card, quality report, limitations, threat model, license status, and claim matrix exist"
            if not document_failures else "required publication documents are missing or malformed",
            document_failures,
        )
    )

    lineage_failures = _verify_publication_items(staging_root, report_root)
    checks.append(
        _check(
            "FINAL-PAPER-LINEAGE-001", 10, not lineage_failures,
            f"failures={len(lineage_failures)}",
            "every declared paper table or figure binds to immutable staged source bytes",
            "paper item lineage is complete" if not lineage_failures
            else "paper item lineage is incomplete or disagrees with source bytes",
            lineage_failures[:16],
        )
    )

    wording_hits: list[str] = []
    for path in sorted(item for item in report_root.rglob("*") if item.is_file()):
        if path.suffix.lower() not in {".md", ".csv", ".html", ".json"}:
            continue
        lowered = path.read_text(encoding="utf-8").lower()
        for phrase in FORBIDDEN_REPORT_PHRASES:
            if phrase in lowered:
                wording_hits.append(f"{path.relative_to(staging_root).as_posix()}:{phrase}")
    checks.append(
        _check(
            "FINAL-WORDING-001", 13, not wording_hits,
            f"forbidden_phrase_hits={len(wording_hits)}", "zero forbidden claim-language matches",
            "report claim language remains within the generator evidence boundary" if not wording_hits
            else "one or more reports contain forbidden claim language",
            wording_hits[:16],
        )
    )
    return _result(preliminary.study_id, checks, raise_on_failure=True)


def _validation_index(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[dict[tuple[str, int, str], Mapping[str, Any]], tuple[str, ...]]:
    index: dict[tuple[str, int, str], Mapping[str, Any]] = {}
    errors: list[str] = []
    for row in rows:
        if str(row.get("evidence_phase")) != "final_S15":
            continue
        key = (
            str(row["condition_id"]), int(row["replicate_id"]), str(row["check_id"])
        )
        if key in index:
            errors.append(f"duplicate:{key[0]}/{key[1]}/{key[2]}")
        index[key] = row
    return index, tuple(errors)


def _domain_validation_checks(
    index: Mapping[tuple[str, int, str], Mapping[str, Any]],
    expected_keys: set[tuple[str, int]],
    definitions: Iterable[tuple[str, int, tuple[str, ...], str]],
) -> list[FinalReleaseCheck]:
    output: list[FinalReleaseCheck] = []
    for gate_id, task_number, check_ids, expected in definitions:
        failures: list[str] = []
        for condition_id, replicate_id in sorted(expected_keys):
            for check_id in check_ids:
                row = index.get((condition_id, replicate_id, check_id))
                if row is None or str(row.get("status")) not in {"pass", "not_applicable"}:
                    failures.append(f"{condition_id}/{replicate_id}/{check_id}")
        output.append(
            _check(
                gate_id, task_number, not failures, f"failures={len(failures)}", expected,
                expected if not failures else f"required domain checks failed for {len(failures)} run/check pairs",
                failures[:16],
            )
        )
    return output


def _verify_condition_releases(
    root: Path,
    executed_rows: Sequence[Any],
) -> list[str]:
    if not root.is_dir():
        return [f"condition release root does not exist: {root}"]
    expected_hashes = {
        str(row.artifact_manifest_sha256)
        for row in executed_rows
        if row.artifact_manifest_sha256
    }
    manifests: dict[str, Path] = {}
    for path in sorted(root.rglob("manifest.json")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in manifests:
            return [f"duplicate condition root manifest digest {digest}"]
        manifests[digest] = path
    failures: list[str] = []
    missing = sorted(expected_hashes - set(manifests))
    if missing:
        failures.extend(f"missing manifest {digest}" for digest in missing[:16])
    contract = load_contract()
    for digest in sorted(expected_hashes & set(manifests)):
        manifest_path = manifests[digest]
        release_root = manifest_path.parent
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            if payload.get("authoritative_storage") != "typed_arrow_parquet_zstd":
                raise ValueError("authoritative storage is not typed Arrow/Parquet/ZSTD")
            if payload.get("jsonl_authority") is not False:
                raise ValueError("JSONL authority is not explicitly false")
            rows = _read_parquet_rows(release_root / "artifact_manifest.parquet")
            verify_manifest_closure(release_root, rows=rows, contract=contract)
            required = {
                "publication/reports/claim_matrix.csv",
                "publication/reports/data_card.md",
                "publication/reports/model_card.md",
                "publication/reports/quality_report.json",
            }
            actual = {str(item["relative_path"]) for item in payload["artifacts"]}
            if required - actual:
                raise ValueError(f"missing S15 reports {sorted(required - actual)}")
        except Exception as exc:
            failures.append(f"{release_root}: {type(exc).__name__}: {exc}")
    return failures


def _read_parquet_rows(path: Path) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("pyarrow is required for the final release gate") from exc
    parquet = pq.ParquetFile(path)
    try:
        return parquet.read().to_pylist()
    finally:
        parquet.close()


def _verify_publication_items(staging_root: Path, report_root: Path) -> list[str]:
    path = report_root / "publication_items.json"
    if not path.is_file():
        return ["publication_items.json is missing"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"publication_items.json cannot be read: {exc}"]
    if payload.get("format") != "htgl.publication-item-lineage.v1":
        return ["publication_items.json has an unsupported format"]
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        return ["publication_items.json must declare at least one paper table"]
    failures: list[str] = []
    seen: set[str] = set()
    for item in items:
        item_id = str(item.get("item_id", ""))
        if not item_id or item_id in seen:
            failures.append(f"invalid or duplicate publication item ID {item_id!r}")
            continue
        seen.add(item_id)
        item_kind = str(item.get("item_kind", ""))
        if item_kind not in {"table", "figure"}:
            failures.append(f"{item_id}: unsupported item_kind {item_kind!r}")
        output_relative = str(item.get("output_path", ""))
        if not output_relative or not (staging_root / output_relative).is_file():
            failures.append(f"{item_id}: missing generated output {output_relative!r}")
        sources = item.get("sources")
        if not isinstance(sources, list) or not sources:
            failures.append(f"{item_id}: no immutable sources")
            continue
        for source in sources:
            relative = str(source.get("relative_path", ""))
            source_path = staging_root / relative
            if not source_path.is_file():
                failures.append(f"{item_id}: missing source {relative}")
                continue
            digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
            if digest != str(source.get("sha256", "")):
                failures.append(f"{item_id}: digest mismatch for {relative}")
    declared_figures = {
        str(item.get("output_path"))
        for item in items
        if item.get("item_kind") == "figure"
    }
    actual_figures = {
        item.relative_to(staging_root).as_posix()
        for item in report_root.rglob("*")
        if item.is_file() and item.suffix.lower() in {".png", ".svg", ".pdf"}
    }
    if declared_figures != actual_figures:
        failures.append(
            f"figure inventory mismatch missing={sorted(actual_figures-declared_figures)} extra={sorted(declared_figures-actual_figures)}"
        )
    return failures


def _result(
    study_id: str,
    checks: Sequence[FinalReleaseCheck],
    *,
    raise_on_failure: bool,
) -> FinalReleaseGateResult:
    ordered = tuple(sorted(checks, key=lambda item: (item.task_number, item.check_id)))
    eligible = all(item.status == "pass" for item in ordered)
    digest = domain_sha256(
        "P8-final-release-gate-v1",
        {"study_id": study_id, "checks": [asdict(item) for item in ordered]},
    )
    result = FinalReleaseGateResult(study_id, ordered, eligible, digest)
    if raise_on_failure and not eligible:
        raise FinalReleaseGateError(ordered)
    return result


def _check(
    check_id: str,
    task_number: int,
    passed: bool,
    observed: str,
    expected: str,
    message: str,
    affected_ids: Iterable[str] = (),
) -> FinalReleaseCheck:
    return FinalReleaseCheck(
        check_id, task_number, "pass" if passed else "fail", observed, expected,
        message, tuple(str(item) for item in affected_ids),
    )


def _failure(
    check_id: str,
    task_number: int,
    observed: str,
    expected: str,
    message: str,
    affected_ids: Iterable[str] = (),
) -> FinalReleaseCheck:
    return _check(check_id, task_number, False, observed, expected, message, affected_ids)


def _key_strings(keys: Iterable[tuple[str, int]]) -> tuple[str, ...]:
    return tuple(f"{condition_id}/{replicate_id}" for condition_id, replicate_id in keys)
