"""Independent golden policy cases and configured accuracy gates."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.policy.package import (
    PolicyPackage,
    PolicyPackageError,
    SafePolicyEvaluator,
)
from htgl_dataset_generator.policy.language import POLICY_ACTIONS


GOLDEN_SUITE_FORMAT = "htgl.policy.golden-suite.v1"
DEFAULT_GOLDEN_RELATIVE_PATH = Path("policies") / "golden" / "htgl_reference_policy_cases_v1.json"
REQUIRED_GOLDEN_CATEGORIES = frozenset(
    {
        "boundary_dates",
        "conflicting_rules",
        "exemptions",
        "cross_jurisdiction_transfers",
        "null_unknown_facts",
        "consent_withdrawal",
        "erasure_scope",
        "retention_exception",
    }
)


@dataclass(frozen=True)
class GoldenSuiteResult:
    golden_suite_id: str
    case_count: int
    exact_match_count: int
    decision_accuracy: float
    conflict_case_count: int
    conflict_resolution_agreement: float
    failures: tuple[str, ...]


def evaluate_golden_suite(
    package: PolicyPackage,
    evaluator: SafePolicyEvaluator,
    path: Path | None = None,
) -> GoldenSuiteResult:
    """Evaluate separately authored literal cases against the policy package."""

    suite_path = path.resolve() if path is not None else _repo_root() / DEFAULT_GOLDEN_RELATIVE_PATH
    try:
        raw = json.loads(suite_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyPackageError(f"golden policy suite not found: {suite_path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyPackageError(f"invalid golden policy JSON {suite_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise PolicyPackageError("golden policy suite root must be an object")
    _exact_keys(
        raw,
        {
            "suite_format",
            "golden_suite_id",
            "policy_profile_id",
            "policy_version",
            "authorship",
            "cases",
        },
        "golden suite",
    )
    if raw["suite_format"] != GOLDEN_SUITE_FORMAT:
        raise PolicyPackageError(f"golden suite format must be {GOLDEN_SUITE_FORMAT}")
    if raw["golden_suite_id"] != package.golden_suite_id:
        raise PolicyPackageError("golden_suite_id does not match policy package")
    if raw["policy_profile_id"] != package.policy_profile_id or raw["policy_version"] != package.version:
        raise PolicyPackageError("golden suite policy profile/version does not match package")
    if raw["authorship"] != "independently_authored_literal_expected_outcomes":
        raise PolicyPackageError("golden suite must declare independent literal expected outcomes")
    cases = raw["cases"]
    if not isinstance(cases, list) or not cases:
        raise PolicyPackageError("golden suite cases must be a non-empty list")

    failures: list[str] = []
    exact_matches = 0
    decision_matches = 0
    conflict_cases = 0
    conflict_matches = 0
    seen_case_ids: set[str] = set()
    observed_categories: set[str] = set()
    package_rule_ids = {rule.policy_rule_id for rule in package.rules}
    package_violation_types = {rule.violation_type for rule in package.rules}
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise PolicyPackageError(f"golden case {index} must be an object")
        _exact_keys(
            case,
            {
                "case_id",
                "category",
                "description",
                "facts",
                "expected",
                "is_conflict_case",
            },
            f"golden case {index}",
        )
        case_id = _nonempty_string(case["case_id"], f"golden case {index}.case_id")
        if case_id in seen_case_ids:
            raise PolicyPackageError(f"duplicate golden case_id={case_id!r}")
        seen_case_ids.add(case_id)
        category = _nonempty_string(case["category"], f"{case_id}.category")
        observed_categories.add(category)
        _nonempty_string(case["description"], f"{case_id}.description")
        if not isinstance(case["facts"], Mapping):
            raise PolicyPackageError(f"{case_id}.facts must be an object")
        expected = case["expected"]
        if not isinstance(expected, Mapping):
            raise PolicyPackageError(f"{case_id}.expected must be an object")
        _exact_keys(
            expected,
            {
                "expected_action",
                "observed_action",
                "is_violation",
                "violation_type",
                "requires_retention",
                "requires_erasure",
                "is_cross_region",
                "winning_rule_id",
                "required_applied_rule_ids",
            },
            f"{case_id}.expected",
        )
        _validate_expected_outcome(
            expected,
            case_id=case_id,
            package_rule_ids=package_rule_ids,
            package_violation_types=package_violation_types,
        )
        evaluation = evaluator.evaluate(case["facts"])
        decision_match = (
            evaluation.expected_action == expected["expected_action"]
            and evaluation.is_violation is expected["is_violation"]
        )
        if decision_match:
            decision_matches += 1
        required_rule_ids = expected["required_applied_rule_ids"]
        if not isinstance(required_rule_ids, list) or not required_rule_ids:
            raise PolicyPackageError(f"{case_id}.required_applied_rule_ids must be non-empty")
        full_match = (
            decision_match
            and evaluation.observed_action == expected["observed_action"]
            and evaluation.violation_type == expected["violation_type"]
            and evaluation.requires_retention is expected["requires_retention"]
            and evaluation.requires_erasure is expected["requires_erasure"]
            and evaluation.is_cross_region is expected["is_cross_region"]
            and evaluation.winning_rule_id == expected["winning_rule_id"]
            and set(required_rule_ids).issubset(evaluation.applied_rule_ids)
            and bool(evaluation.applied_rule_ids)
            and bool(evaluation.conflict_resolution_trace)
            and bool(evaluation.explanation_code)
        )
        if full_match:
            exact_matches += 1
        else:
            failures.append(
                f"{case_id}: expected={dict(expected)!r} observed="
                f"{{'expected_action': {evaluation.expected_action!r}, "
                f"'observed_action': {evaluation.observed_action!r}, "
                f"'is_violation': {evaluation.is_violation!r}, "
                f"'violation_type': {evaluation.violation_type!r}, "
                f"'requires_retention': {evaluation.requires_retention!r}, "
                f"'requires_erasure': {evaluation.requires_erasure!r}, "
                f"'is_cross_region': {evaluation.is_cross_region!r}, "
                f"'winning_rule_id': {evaluation.winning_rule_id!r}}}"
            )
        is_conflict_case = case["is_conflict_case"]
        if not isinstance(is_conflict_case, bool):
            raise PolicyPackageError(f"{case_id}.is_conflict_case must be boolean")
        if is_conflict_case:
            conflict_cases += 1
            if evaluation.winning_rule_id == expected["winning_rule_id"]:
                conflict_matches += 1

    missing_categories = sorted(REQUIRED_GOLDEN_CATEGORIES - observed_categories)
    if missing_categories:
        raise PolicyPackageError(
            f"golden suite is missing required case categories {missing_categories}"
        )

    case_count = len(cases)
    return GoldenSuiteResult(
        golden_suite_id=str(raw["golden_suite_id"]),
        case_count=case_count,
        exact_match_count=exact_matches,
        decision_accuracy=decision_matches / case_count,
        conflict_case_count=conflict_cases,
        conflict_resolution_agreement=(conflict_matches / conflict_cases if conflict_cases else 1.0),
        failures=tuple(failures),
    )


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise PolicyPackageError(f"cannot locate repository root from {start}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise PolicyPackageError(
            f"{label} keys must be {sorted(expected)}, got {sorted(value)}"
        )


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyPackageError(f"{label} must be a non-empty string")
    return value


def _validate_expected_outcome(
    expected: Mapping[str, Any],
    *,
    case_id: str,
    package_rule_ids: set[str],
    package_violation_types: set[str],
) -> None:
    for field in ("expected_action", "observed_action"):
        value = expected[field]
        if value not in POLICY_ACTIONS:
            raise PolicyPackageError(f"{case_id}.{field}={value!r} is not a policy action")
    for field in ("is_violation", "requires_retention", "requires_erasure", "is_cross_region"):
        if not isinstance(expected[field], bool):
            raise PolicyPackageError(f"{case_id}.{field} must be boolean")
    violation_type = expected["violation_type"]
    if violation_type not in package_violation_types:
        raise PolicyPackageError(
            f"{case_id}.violation_type={violation_type!r} is not declared by the package"
        )
    winning_rule_id = expected["winning_rule_id"]
    if winning_rule_id not in package_rule_ids:
        raise PolicyPackageError(
            f"{case_id}.winning_rule_id={winning_rule_id!r} is not declared by the package"
        )
    required_rule_ids = expected["required_applied_rule_ids"]
    if not isinstance(required_rule_ids, list) or not required_rule_ids:
        raise PolicyPackageError(f"{case_id}.required_applied_rule_ids must be non-empty")
    if any(not isinstance(rule_id, str) or not rule_id for rule_id in required_rule_ids):
        raise PolicyPackageError(f"{case_id}.required_applied_rule_ids must contain rule IDs")
    if len(set(required_rule_ids)) != len(required_rule_ids):
        raise PolicyPackageError(f"{case_id}.required_applied_rule_ids contains duplicates")
    unknown_rule_ids = sorted(set(required_rule_ids) - package_rule_ids)
    if unknown_rule_ids:
        raise PolicyPackageError(
            f"{case_id}.required_applied_rule_ids contains unknown rules {unknown_rule_ids}"
        )
