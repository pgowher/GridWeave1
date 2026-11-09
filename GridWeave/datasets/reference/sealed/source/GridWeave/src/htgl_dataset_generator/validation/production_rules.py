"""Final production-rule audit and publication gates.

The checks in this module are intentionally fail-closed. They do not certify
legal compliance, deletion, operational HTGL execution, or cryptographic proof.
They only reject artifact sets and repository states that violate the generator
boundary and deterministic benchmark contract.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from tokenize import COMMENT, generate_tokens
from typing import Any, Iterable, Mapping, Sequence
import math

from htgl_dataset_generator.config import (
    CORE_VALIDATION_CHECK_IDS,
    ConfigResolutionError,
    ResolvedConfig,
    resolve_config_file,
)
from htgl_dataset_generator.schemas import ContractSpec, SchemaValidationError, load_contract, validate_record


ERROR = "error"
FATAL = "fatal"
PUBLIC_RELEASE_PROFILE = "public"
OBSERVER_RELEASE_PROFILE = "observer"
INTERNAL_RELEASE_PROFILE = "internal"
EVALUATOR_ONLY_TRUTH_TABLES = frozenset(
    {
        "policy_decision_truth",
        "anomaly_instance",
        "observer_event",
        "sample_membership",
    }
)
AUTHORITATIVE_MEDIA_TYPE = "application/parquet"
JSONL_COMPATIBILITY_ADAPTER = "jsonl_debug_view"
REQUIRED_PUBLICATION_TABLES = frozenset({"validation_issue", "run_metric", "artifact_manifest"})
REQUIRED_CLAIM_MATRIX_KEYS = frozenset(
    {
        "represented_population",
        "materialized_rows",
        "executed_operations",
        "generator_boundary",
        "legal_compliance_claim",
        "real_deletion_claim",
        "cryptographic_proof_scope",
        "operational_execution_claim",
    }
)
WEIGHTED_METRIC_MODES = frozenset({"HT", "Hajek", "analytic"})


class ProductionRuleViolation(ValueError):
    """Raised when a final production rule is violated."""


@dataclass(frozen=True)
class ProductionRuleIssue:
    rule_id: str
    severity: str
    location: str
    message: str


@dataclass(frozen=True)
class ProductionRuleAuditReport:
    issues: tuple[ProductionRuleIssue, ...]
    scanned_python_files: int
    checked_configs: int

    @property
    def passed(self) -> bool:
        return not any(issue.severity in {ERROR, FATAL} for issue in self.issues)

    def raise_for_errors(self) -> None:
        if self.passed:
            return
        messages = "; ".join(
            f"{issue.rule_id} at {issue.location}: {issue.message}" for issue in self.issues
        )
        raise ProductionRuleViolation(messages)


def audit_repository_final_rules(
    repo_root: str | Path,
    *,
    config_paths: Iterable[str | Path] | None = None,
    contract: ContractSpec | None = None,
) -> ProductionRuleAuditReport:
    """Audit implemented stages against the final production rules."""

    root = Path(repo_root).resolve()
    schema_contract = contract if contract is not None else load_contract()
    source_root = root / "src" / "htgl_dataset_generator"
    issues: list[ProductionRuleIssue] = []
    python_files = tuple(_python_source_files(source_root))
    if not python_files:
        issues.append(
            ProductionRuleIssue(
                "FPR-1",
                FATAL,
                str(source_root),
                "no Python source files found under src/htgl_dataset_generator",
            )
        )
    for path in python_files:
        issues.extend(_audit_python_source_file(path, root))

    if config_paths is None:
        discovered_configs = tuple(sorted((root / "configs").glob("*.json")))
    else:
        discovered_configs = tuple(Path(path).resolve() for path in config_paths)
    for config_path in discovered_configs:
        try:
            resolved = resolve_config_file(config_path, contract=schema_contract)
        except (ConfigResolutionError, FileNotFoundError, SchemaValidationError, ValueError) as exc:
            issues.append(
                ProductionRuleIssue(
                    "FPR-CONFIG",
                    FATAL,
                    _display_path(config_path, root),
                    f"configuration cannot resolve fail-closed: {exc}",
                )
            )
            continue
        issues.extend(audit_resolved_config(resolved, contract=schema_contract))

    return ProductionRuleAuditReport(
        issues=tuple(issues),
        scanned_python_files=len(python_files),
        checked_configs=len(discovered_configs),
    )


def audit_resolved_config(
    resolved: ResolvedConfig,
    *,
    contract: ContractSpec | None = None,
) -> tuple[ProductionRuleIssue, ...]:
    """Audit one resolved config for N/n/q and storage-authority discipline."""

    schema_contract = contract if contract is not None else load_contract()
    issues: list[ProductionRuleIssue] = []
    location = resolved.source_path or resolved.run.run_id

    if resolved.output.schema_contract_id != schema_contract.contract_id:
        issues.append(
            ProductionRuleIssue(
                "FPR-3",
                ERROR,
                location,
                "output.schema_contract_id does not match the locked contract",
            )
        )
    if resolved.output.schema_contract_fingerprint != schema_contract.contract_fingerprint:
        issues.append(
            ProductionRuleIssue(
                "FPR-3",
                ERROR,
                location,
                "output.schema_contract_fingerprint does not match the locked contract",
            )
        )
    if resolved.output.parquet_compression.upper() != "ZSTD":
        issues.append(
            ProductionRuleIssue(
                "FPR-3",
                ERROR,
                location,
                "authoritative storage must be Arrow/Parquet with ZSTD compression",
            )
        )
    if resolved.output.output_profile_id.lower().endswith("jsonl"):
        issues.append(
            ProductionRuleIssue(
                "FPR-3",
                ERROR,
                location,
                "JSONL output profile cannot be authoritative",
            )
        )
    normalized_adapters = tuple(adapter.lower() for adapter in resolved.output.adapters)
    if "jsonl" in normalized_adapters:
        issues.append(
            ProductionRuleIssue(
                "FPR-3",
                ERROR,
                location,
                "bare JSONL adapter is ambiguous; use jsonl_debug_view for non-authoritative compatibility output",
            )
        )
    for adapter in normalized_adapters:
        if (adapter == "jsonl" or adapter.startswith("jsonl_")) and adapter != JSONL_COMPATIBILITY_ADAPTER:
            issues.append(
                ProductionRuleIssue(
                    "FPR-3",
                    ERROR,
                    location,
                    "JSONL-like adapters must be named jsonl_debug_view and must remain non-authoritative",
                )
            )
    if JSONL_COMPATIBILITY_ADAPTER in normalized_adapters:
        expected_schema_ids = tuple(table.schema_id for table in schema_contract.tables)
        if resolved.output.table_schema_ids != expected_schema_ids:
            issues.append(
                ProductionRuleIssue(
                    "FPR-3",
                    ERROR,
                    location,
                    "JSONL adapters are allowed only as compatibility views over the full locked schema set",
                )
            )

    n_represented = resolved.claim_scale.represented_population
    n_materialized = resolved.claim_scale.materialized_row_target
    q_executed = resolved.claim_scale.executed_operation_target
    if n_represented <= 0 or n_materialized <= 0:
        issues.append(
            ProductionRuleIssue("FPR-8", ERROR, location, "N and n must be positive and explicit")
        )
    if n_materialized > n_represented:
        issues.append(
            ProductionRuleIssue("FPR-8", ERROR, location, "materialized n cannot exceed represented N")
        )
    if q_executed is None and resolved.claim_scale.operational_claim_allowed:
        issues.append(
            ProductionRuleIssue(
                "FPR-8",
                ERROR,
                location,
                "operational claims require explicit executed_operation_target q",
            )
        )
    if q_executed is not None and q_executed > n_materialized:
        issues.append(
            ProductionRuleIssue(
                "FPR-8",
                ERROR,
                location,
                "executed q cannot exceed materialized n without an explicit replay workload artifact",
            )
        )
    if n_represented >= 100_000_000 and (
        q_executed is not None or resolved.claim_scale.operational_claim_allowed
    ):
        issues.append(
            ProductionRuleIssue(
                "FPR-8",
                ERROR,
                location,
                "represented-population scale configs must not imply population-scale execution",
            )
        )
    if q_executed is None and "execution" in resolved.claim_scale.replay_semantics.lower():
        if "no_downstream_execution" not in resolved.claim_scale.replay_semantics.lower():
            issues.append(
                ProductionRuleIssue(
                    "FPR-8",
                    ERROR,
                    location,
                    "replay_semantics mentions execution while q is not declared",
                )
            )

    return tuple(issues)


def validate_release_table_privacy(
    table_names: Iterable[str],
    *,
    release_profile: str = PUBLIC_RELEASE_PROFILE,
    contract: ContractSpec | None = None,
) -> None:
    """Reject table sets that would leak truth-sidecar or restricted tables."""

    schema_contract = contract if contract is not None else load_contract()
    names = tuple(table_names)
    unknown = sorted(set(names) - set(schema_contract.table_names))
    if unknown:
        raise ProductionRuleViolation(f"release contains unknown table names: {unknown}")
    if release_profile == INTERNAL_RELEASE_PROFILE:
        return
    for table_name in names:
        table = schema_contract.table(table_name)
        if release_profile == PUBLIC_RELEASE_PROFILE and table.privacy_class != "public":
            raise ProductionRuleViolation(
                f"public release cannot include {table_name} with privacy_class={table.privacy_class}"
            )
        if release_profile == OBSERVER_RELEASE_PROFILE:
            if table_name in EVALUATOR_ONLY_TRUTH_TABLES or table.privacy_class in {"evaluator_only", "sealed"}:
                raise ProductionRuleViolation(
                    f"observer release cannot include evaluator-only truth table {table_name}"
                )
        if release_profile not in {PUBLIC_RELEASE_PROFILE, OBSERVER_RELEASE_PROFILE}:
            raise ProductionRuleViolation(f"unknown release_profile={release_profile!r}")


def validate_population_metric_eligibility(
    run_metrics: Iterable[Mapping[str, Any]],
    sample_memberships: Iterable[Mapping[str, Any]] | None,
) -> None:
    """Require valid inclusion probabilities for weighted population estimates."""

    metrics = tuple(run_metrics)
    weighted_metrics = [
        row
        for row in metrics
        if str(row.get("weighting")) in WEIGHTED_METRIC_MODES
        or "population" in str(row.get("metric_name", "")).lower()
        or "estimate" in str(row.get("metric_name", "")).lower()
    ]
    if not weighted_metrics:
        return
    memberships = tuple(sample_memberships or ())
    if not memberships:
        raise ProductionRuleViolation(
            "weighted or population-estimate metrics require sample_membership rows"
        )
    memberships_by_design: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for index, row in enumerate(memberships):
        memberships_by_design.setdefault(str(row.get("sample_design_id", "")), []).append(
            (index, row)
        )
        probability = float(row.get("first_order_inclusion_probability", 0.0))
        design_weight = float(row.get("design_weight", 0.0))
        analysis_weight = float(row.get("analysis_weight", 0.0))
        if not (0.0 < probability <= 1.0):
            raise ProductionRuleViolation(
                f"sample_membership[{index}] has invalid first_order_inclusion_probability={probability}"
            )
        if not (math.isfinite(design_weight) and design_weight > 0):
            raise ProductionRuleViolation(f"sample_membership[{index}] has invalid design_weight={design_weight}")
        if not (math.isfinite(analysis_weight) and analysis_weight > 0):
            raise ProductionRuleViolation(
                f"sample_membership[{index}] has invalid analysis_weight={analysis_weight}"
            )
    for metric in weighted_metrics:
        metric_name = str(metric.get("metric_name", ""))
        parts = metric_name.split(".")
        design_id = (
            parts[1]
            if len(parts) >= 3 and parts[0] == "sampling" and parts[1] in memberships_by_design
            else None
        )
        relevant = (
            memberships_by_design[design_id]
            if design_id is not None
            else [(index, row) for index, row in enumerate(memberships)]
        )
        if not relevant:
            raise ProductionRuleViolation(
                f"population metric {metric_name!r} has no matching sample membership rows"
            )
        ineligible = [index for index, row in relevant if row.get("estimator_eligible") is not True]
        if ineligible:
            raise ProductionRuleViolation(
                f"population metric {metric_name!r} uses estimator-ineligible memberships {ineligible[:8]}"
            )


def validate_publication_gate(
    tables: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    claim_matrix: Mapping[str, Any],
    required_check_ids: Iterable[str] = CORE_VALIDATION_CHECK_IDS,
    contract: ContractSpec | None = None,
) -> None:
    """Validate the final publication gate for benchmark artifacts."""

    schema_contract = contract if contract is not None else load_contract()
    missing = sorted(REQUIRED_PUBLICATION_TABLES - set(tables))
    if missing:
        raise ProductionRuleViolation(f"publication requires tables {missing}")
    missing_claims = sorted(REQUIRED_CLAIM_MATRIX_KEYS - set(claim_matrix))
    if missing_claims:
        raise ProductionRuleViolation(f"publication requires claim matrix keys {missing_claims}")
    if bool(claim_matrix.get("legal_compliance_claim")):
        raise ProductionRuleViolation("publication cannot claim legal compliance")
    if bool(claim_matrix.get("real_deletion_claim")):
        raise ProductionRuleViolation("publication cannot claim real deletion")
    if bool(claim_matrix.get("operational_execution_claim")) and not claim_matrix.get("executed_operations"):
        raise ProductionRuleViolation("operational execution claim requires explicit executed_operations q")

    for table_name, rows in tables.items():
        for index, row in enumerate(rows):
            try:
                validate_record(schema_contract, table_name, row)
            except Exception as exc:
                raise ProductionRuleViolation(f"{table_name}[{index}] violates locked schema: {exc}") from exc

    validate_required_check_execution(
        tables["validation_issue"],
        required_check_ids=required_check_ids,
    )

    for index, artifact in enumerate(tables["artifact_manifest"]):
        if bool(artifact["publication_eligible"]):
            if artifact["privacy_class"] != "public":
                raise ProductionRuleViolation(
                    f"artifact_manifest[{index}] is publication_eligible but privacy_class={artifact['privacy_class']}"
                )
            if artifact["schema_id"] is not None and artifact["media_type"] != AUTHORITATIVE_MEDIA_TYPE:
                raise ProductionRuleViolation(
                    f"artifact_manifest[{index}] has schema_id but media_type={artifact['media_type']}; "
                    "authoritative dataset tables must publish as Parquet"
                )

    validate_population_metric_eligibility(
        tables["run_metric"],
        tables.get("sample_membership"),
    )


def validate_required_check_execution(
    validation_issues: Iterable[Mapping[str, Any]],
    *,
    required_check_ids: Iterable[str] = CORE_VALIDATION_CHECK_IDS,
) -> None:
    """Reject missing, unexecuted, failed, or unjustified required checks."""

    rows = tuple(validation_issues)
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        check_id = str(row.get("check_id", ""))
        if not check_id:
            raise ProductionRuleViolation(f"validation_issue[{index}] has an empty check_id")
        if check_id in by_id:
            raise ProductionRuleViolation(f"duplicate validation check row {check_id}")
        by_id[check_id] = row
    required = set(required_check_ids)
    missing = sorted(required - set(by_id))
    if missing:
        raise ProductionRuleViolation(f"publication is missing required validation checks {missing}")
    for check_id, row in sorted(by_id.items()):
        severity = str(row.get("severity"))
        status = str(row.get("status"))
        message = str(row.get("message", ""))
        if status == "pass":
            continue
        if status == "not_applicable":
            if not message.startswith("justification_code="):
                raise ProductionRuleViolation(
                    f"validation check {check_id} is not_applicable without explicit justification"
                )
            continue
        if check_id in required or severity in {"error", "fatal"}:
            raise ProductionRuleViolation(
                f"validation check {check_id} is unresolved: severity={severity}, status={status}"
            )


def _python_source_files(source_root: Path) -> Iterable[Path]:
    if not source_root.exists():
        return ()
    return tuple(
        path
        for path in sorted(source_root.rglob("*.py"))
        if "__pycache__" not in path.parts
    )


def _audit_python_source_file(path: Path, root: Path) -> tuple[ProductionRuleIssue, ...]:
    issues: list[ProductionRuleIssue] = []
    display = _display_path(path, root)
    source = path.read_text(encoding="utf-8")
    issues.extend(_audit_comment_markers(source, display))
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return (
            ProductionRuleIssue(
                "FPR-1",
                FATAL,
                f"{display}:{exc.lineno or 1}",
                f"source cannot be parsed: {exc.msg}",
            ),
        )

    if path.name != "__init__.py" and not _has_implementation_surface(tree):
        issues.append(
            ProductionRuleIssue(
                "FPR-1",
                ERROR,
                display,
                "module has no implementation surface and would be a placeholder module",
            )
        )

    aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "random":
                    issues.append(_source_issue("FPR-4", display, node, "random module import is forbidden"))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "random":
                issues.append(_source_issue("FPR-4", display, node, "random module import is forbidden"))
            for alias in node.names:
                if module == "uuid" and alias.name == "uuid4":
                    issues.append(_source_issue("FPR-4", display, node, "uuid4 import is forbidden"))
        elif isinstance(node, ast.Pass):
            issues.append(_source_issue("FPR-1", display, node, "pass statement is not allowed in implemented source"))
        elif isinstance(node, ast.Raise) and _raises_not_implemented(node):
            issues.append(_source_issue("FPR-1", display, node, "NotImplementedError is not allowed in production source"))
        elif isinstance(node, ast.Call):
            call_name = _resolved_call_name(node.func, aliases)
            violation = _determinism_violation(call_name)
            if violation is not None:
                issues.append(_source_issue("FPR-4", display, node, violation))
            approximation = _approximation_violation(call_name)
            if approximation is not None:
                issues.append(_source_issue("FPR-5", display, node, approximation))
    return tuple(issues)


def _audit_comment_markers(source: str, display: str) -> tuple[ProductionRuleIssue, ...]:
    issues: list[ProductionRuleIssue] = []
    for token in generate_tokens(StringIO(source).readline):
        if token.type != COMMENT:
            continue
        comment = token.string.lower()
        if "todo" in comment or "fixme" in comment:
            issues.append(
                ProductionRuleIssue(
                    "FPR-1",
                    ERROR,
                    f"{display}:{token.start[0]}",
                    "source comment leaves TODO/FIXME work inside implemented stages",
                )
            )
    return tuple(issues)


def _has_implementation_surface(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and not _is_dunder_assignment(node):
            return True
    return False


def _is_dunder_assignment(node: ast.Assign | ast.AnnAssign) -> bool:
    targets: Sequence[ast.expr]
    if isinstance(node, ast.Assign):
        targets = node.targets
    else:
        targets = (node.target,)
    names = [target.id for target in targets if isinstance(target, ast.Name)]
    return bool(names) and all(name.startswith("__") and name.endswith("__") for name in names)


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible = alias.asname or alias.name.split(".")[0]
                aliases[visible] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                visible = alias.asname or alias.name
                aliases[visible] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def _resolved_call_name(node: ast.AST, aliases: Mapping[str, str]) -> str | None:
    dotted = _dotted_name(node)
    if dotted is None:
        return None
    parts = dotted.split(".")
    if parts[0] in aliases:
        replacement = aliases[parts[0]]
        if len(parts) == 1:
            return replacement
        return ".".join((replacement, *parts[1:]))
    return dotted


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _determinism_violation(call_name: str | None) -> str | None:
    if call_name is None:
        return None
    if call_name in {"uuid.uuid4"} or call_name.endswith(".uuid4"):
        return "UUID4 is forbidden; use deterministic UUIDv5 or content-derived IDs"
    if call_name.startswith("random."):
        return "global random state is forbidden; use named CounterRng streams"
    if ".random." in call_name and call_name.startswith(("numpy.", "np.")):
        return "NumPy random state is forbidden for generator semantics; use named seed streams"
    if call_name in {"time.time", "time.time_ns"}:
        return "wall-clock time is forbidden for deterministic generation semantics"
    if call_name in {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.now", "datetime.utcnow"}:
        return "current wall-clock datetime is forbidden for deterministic generation semantics"
    return None


def _approximation_violation(call_name: str | None) -> str | None:
    if call_name is None:
        return None
    lower = call_name.lower()
    if lower.endswith((".gauss", ".normalvariate")) or ".normal" in lower and ".random." in lower:
        return "normal/Gaussian approximation cannot be used as an exact arrival or count method"
    return None


def _raises_not_implemented(node: ast.Raise) -> bool:
    exc = node.exc
    if exc is None:
        return False
    if isinstance(exc, ast.Call):
        return _dotted_name(exc.func) == "NotImplementedError"
    if isinstance(exc, ast.Name):
        return exc.id == "NotImplementedError"
    return False


def _source_issue(rule_id: str, display: str, node: ast.AST, message: str) -> ProductionRuleIssue:
    return ProductionRuleIssue(rule_id, ERROR, f"{display}:{getattr(node, 'lineno', 1)}", message)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
