"""Versioned policy package and deterministic safe rule evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.policy.language import (
    POLICY_ACTIONS,
    PolicyLanguageError,
    canonical_json,
    evaluate_validated_expression,
    normalize_policy_facts,
    validate_expression,
)
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record


PACKAGE_FORMAT = "htgl.policy.package.v1"
DEFAULT_PACKAGE_RELATIVE_PATH = Path("policies") / "htgl_reference_policy_v1.json"
ACTION_RULE_KINDS = frozenset({"permission", "prohibition", "duty", "disclosure"})


class PolicyPackageError(ValueError):
    """Raised when a policy package or evaluation violates its contract."""


@dataclass(frozen=True)
class PolicyRule:
    policy_rule_id: str
    policy_profile_id: str
    version: str
    jurisdiction_id: str | None
    rule_kind: str
    action: str
    asset_selector: Mapping[str, Any]
    party_selector: Mapping[str, Any]
    purpose_selector: Mapping[str, Any] | None
    condition: Mapping[str, Any]
    priority: int
    effective_from: str
    effective_to: str | None
    source_id: str
    source_citation: str
    source_sha256: str
    violation_type: str
    specificity: int
    effective_from_value: datetime
    effective_to_value: datetime | None

    def as_record(self) -> dict[str, Any]:
        return {
            "policy_rule_id": self.policy_rule_id,
            "policy_profile_id": self.policy_profile_id,
            "version": self.version,
            "jurisdiction_id": self.jurisdiction_id,
            "rule_kind": self.rule_kind,
            "action": self.action,
            "asset_selector": canonical_json(self.asset_selector),
            "party_selector": canonical_json(self.party_selector),
            "purpose_selector": canonical_json(self.purpose_selector)
            if self.purpose_selector is not None
            else None,
            "condition_expression": canonical_json(self.condition),
            "priority": self.priority,
            "effective_from": self.effective_from,
            "effective_to": self.effective_to,
            "source_citation": self.source_citation,
            "source_sha256": self.source_sha256,
        }

    def matches(self, facts: Mapping[str, Any], timestamp: datetime) -> bool:
        if timestamp < self.effective_from_value:
            return False
        if self.effective_to_value is not None and timestamp > self.effective_to_value:
            return False
        if self.jurisdiction_id is not None and self.jurisdiction_id not in facts["scope.jurisdictions"]:
            return False
        return (
            evaluate_validated_expression(self.asset_selector, facts)
            and evaluate_validated_expression(self.party_selector, facts)
            and (
                self.purpose_selector is None
                or evaluate_validated_expression(self.purpose_selector, facts)
            )
            and evaluate_validated_expression(self.condition, facts)
        )


@dataclass(frozen=True)
class PolicyPackage:
    package_format: str
    policy_profile_id: str
    version: str
    oracle_version: str
    conflict_strategy: str
    evaluator_profile: str
    golden_suite_id: str
    package_sha256: str
    rules: tuple[PolicyRule, ...]

    def rule_records(self) -> tuple[dict[str, Any], ...]:
        return tuple(rule.as_record() for rule in self.rules)


@dataclass(frozen=True)
class PolicyEvaluation:
    event_id: str
    expected_action: str
    observed_action: str
    is_violation: bool
    violation_type: str
    requires_retention: bool
    requires_erasure: bool
    is_cross_region: bool
    applied_rule_ids: tuple[str, ...]
    conflict_resolution_trace: tuple[str, ...]
    explanation_code: str
    winning_rule_id: str


class SafePolicyEvaluator:
    """Evaluate a fixed policy package without executing policy-supplied code."""

    def __init__(self, package: PolicyPackage):
        self._package = package

    @property
    def package(self) -> PolicyPackage:
        return self._package

    def evaluate(self, raw_facts: Mapping[str, Any]) -> PolicyEvaluation:
        try:
            facts = normalize_policy_facts(raw_facts)
        except PolicyLanguageError as exc:
            raise PolicyPackageError(f"cannot normalize policy facts: {exc}") from exc
        event_time = _parse_timestamp(str(facts["event.timestamp"]), "event.timestamp")
        applicable = tuple(rule for rule in self._package.rules if rule.matches(facts, event_time))
        if not applicable:
            raise PolicyPackageError(
                f"event {facts['event.id']}: no effective policy rule matched; oracle fails closed"
            )
        ranked = tuple(sorted(applicable, key=_rule_rank))
        action_rules = tuple(rule for rule in ranked if rule.rule_kind in ACTION_RULE_KINDS)
        if not action_rules:
            raise PolicyPackageError(
                f"event {facts['event.id']}: no action rule matched; oracle fails closed"
            )
        action_winner = action_rules[0]
        retention_rules = tuple(rule for rule in ranked if rule.rule_kind == "retention")
        erasure_rules = tuple(rule for rule in ranked if rule.rule_kind == "erasure")
        evidence_rules = tuple(rule for rule in ranked if rule.rule_kind == "evidence")
        retention_winner = retention_rules[0] if retention_rules else None
        erasure_winner = erasure_rules[0] if erasure_rules else None
        evidence_winner = evidence_rules[0] if evidence_rules else None

        expected_action = action_winner.action
        observed_action = str(facts["observed.action"])
        is_violation = expected_action != observed_action
        violation_type = (
            _violation_type(action_winner, facts, expected_action)
            if is_violation
            else "none"
        )
        trace = [
            (
                f"candidate:{rule.policy_rule_id}:priority={rule.priority}:"
                f"specificity={rule.specificity}:kind={rule.rule_kind}:action={rule.action}"
            )
            for rule in ranked
        ]
        trace.append(f"action_winner:{action_winner.policy_rule_id}")
        if retention_winner is not None:
            trace.append(f"retention_winner:{retention_winner.policy_rule_id}")
        if erasure_winner is not None:
            trace.append(f"erasure_winner:{erasure_winner.policy_rule_id}")
        if evidence_winner is not None:
            trace.append(f"evidence_winner:{evidence_winner.policy_rule_id}")
        trace.append(f"resolution:{self._package.conflict_strategy}")
        explanation_code = _explanation_code(action_winner)
        return PolicyEvaluation(
            event_id=str(facts["event.id"]),
            expected_action=expected_action,
            observed_action=observed_action,
            is_violation=is_violation,
            violation_type=violation_type,
            requires_retention=retention_winner is not None and retention_winner.action == "retain",
            requires_erasure=erasure_winner is not None and erasure_winner.action == "erase",
            is_cross_region=bool(facts["derived.is_cross_region"]),
            applied_rule_ids=tuple(rule.policy_rule_id for rule in ranked),
            conflict_resolution_trace=tuple(trace),
            explanation_code=explanation_code,
            winning_rule_id=action_winner.policy_rule_id,
        )


def load_policy_package(
    resolved: ResolvedConfig,
    path: Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> PolicyPackage:
    """Load and validate the configured policy package with exact keys."""

    schema_contract = contract if contract is not None else load_contract()
    package_path = path.resolve() if path is not None else _repo_root() / DEFAULT_PACKAGE_RELATIVE_PATH
    try:
        raw = json.loads(package_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyPackageError(f"policy package not found: {package_path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyPackageError(f"invalid policy package JSON {package_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise PolicyPackageError("policy package root must be an object")
    _require_exact_keys(
        raw,
        {
            "package_format",
            "policy_profile_id",
            "version",
            "oracle_version",
            "conflict_strategy",
            "evaluator_profile",
            "golden_suite_id",
            "source_registry",
            "rules",
        },
        "policy package",
    )
    _require(raw["package_format"] == PACKAGE_FORMAT, f"package_format must be {PACKAGE_FORMAT}")
    _require(raw["policy_profile_id"] == resolved.policy.profile_id, "policy_profile_id does not match config")
    _require(raw["version"] == resolved.policy.profile_version, "policy package version does not match config")
    _require(raw["conflict_strategy"] == resolved.policy.conflict_strategy, "conflict strategy does not match config")
    _require(raw["evaluator_profile"] == resolved.policy.evaluator_profile, "evaluator profile does not match config")
    _require(raw["golden_suite_id"] == resolved.policy.golden_suite_id, "golden suite does not match config")
    oracle_version = _required_string(raw["oracle_version"], "oracle_version")
    source_registry = _load_source_registry(raw["source_registry"])
    configured_sources = set(resolved.policy.rule_source_ids)
    if set(source_registry) != configured_sources:
        raise PolicyPackageError(
            "policy source registry must exactly match configured rule_source_ids: "
            f"configured={sorted(configured_sources)} package={sorted(source_registry)}"
        )
    raw_rules = raw["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyPackageError("policy package rules must be a non-empty list")
    rules = tuple(
        _load_rule(
            raw_rule,
            profile_id=str(raw["policy_profile_id"]),
            version=str(raw["version"]),
            source_registry=source_registry,
            contract=schema_contract,
        )
        for raw_rule in raw_rules
    )
    rule_ids = [rule.policy_rule_id for rule in rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise PolicyPackageError("policy package contains duplicate policy_rule_id values")
    required_rule_kinds = set(schema_contract.dictionary_values("rule_kind"))
    observed_rule_kinds = {rule.rule_kind for rule in rules}
    if required_rule_kinds - observed_rule_kinds:
        raise PolicyPackageError(
            f"policy package is missing rule kinds {sorted(required_rule_kinds - observed_rule_kinds)}"
        )
    if not any(rule.rule_kind == "permission" and rule.priority == 0 for rule in rules):
        raise PolicyPackageError("policy package requires an explicit priority-zero permission fallback")
    package_sha256 = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    return PolicyPackage(
        package_format=str(raw["package_format"]),
        policy_profile_id=str(raw["policy_profile_id"]),
        version=str(raw["version"]),
        oracle_version=oracle_version,
        conflict_strategy=str(raw["conflict_strategy"]),
        evaluator_profile=str(raw["evaluator_profile"]),
        golden_suite_id=str(raw["golden_suite_id"]),
        package_sha256=package_sha256,
        rules=tuple(sorted(rules, key=lambda rule: rule.policy_rule_id)),
    )


def _load_source_registry(raw: Any) -> Mapping[str, Mapping[str, str]]:
    if not isinstance(raw, list) or not raw:
        raise PolicyPackageError("source_registry must be a non-empty list")
    registry: dict[str, Mapping[str, str]] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise PolicyPackageError(f"source_registry[{index}] must be an object")
        _require_exact_keys(item, {"source_id", "citation", "assumptions"}, f"source_registry[{index}]")
        source_id = _required_string(item["source_id"], f"source_registry[{index}].source_id")
        citation = _required_string(item["citation"], f"source_registry[{index}].citation")
        assumptions = _required_string(item["assumptions"], f"source_registry[{index}].assumptions")
        if source_id in registry:
            raise PolicyPackageError(f"duplicate source_id={source_id!r}")
        registry[source_id] = {
            "source_id": source_id,
            "citation": citation,
            "assumptions": assumptions,
        }
    return dict(sorted(registry.items()))


def _load_rule(
    raw: Any,
    *,
    profile_id: str,
    version: str,
    source_registry: Mapping[str, Mapping[str, str]],
    contract: ContractSpec,
) -> PolicyRule:
    if not isinstance(raw, Mapping):
        raise PolicyPackageError("each policy rule must be an object")
    _require_exact_keys(
        raw,
        {
            "policy_rule_id",
            "jurisdiction_id",
            "rule_kind",
            "action",
            "asset_selector",
            "party_selector",
            "purpose_selector",
            "condition",
            "priority",
            "effective_from",
            "effective_to",
            "source_id",
            "violation_type",
        },
        "policy rule",
    )
    rule_id = _required_string(raw["policy_rule_id"], "policy_rule_id")
    rule_kind = _required_string(raw["rule_kind"], f"{rule_id}.rule_kind")
    if rule_kind not in contract.dictionary_values("rule_kind"):
        raise PolicyPackageError(f"{rule_id}: unknown rule_kind={rule_kind!r}")
    action = _required_string(raw["action"], f"{rule_id}.action")
    if action not in POLICY_ACTIONS:
        raise PolicyPackageError(f"{rule_id}: unknown policy action={action!r}")
    violation_type = _required_string(raw["violation_type"], f"{rule_id}.violation_type")
    if violation_type not in contract.dictionary_values("violation_type"):
        raise PolicyPackageError(f"{rule_id}: unknown violation_type={violation_type!r}")
    jurisdiction_id = raw["jurisdiction_id"]
    if jurisdiction_id is not None:
        jurisdiction_id = _required_string(jurisdiction_id, f"{rule_id}.jurisdiction_id")
    asset_selector = _expression(raw["asset_selector"], f"{rule_id}.asset_selector")
    party_selector = _expression(raw["party_selector"], f"{rule_id}.party_selector")
    purpose_selector_raw = raw["purpose_selector"]
    purpose_selector = (
        None
        if purpose_selector_raw is None
        else _expression(purpose_selector_raw, f"{rule_id}.purpose_selector")
    )
    condition = _expression(raw["condition"], f"{rule_id}.condition")
    priority = raw["priority"]
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise PolicyPackageError(f"{rule_id}.priority must be an integer")
    if not -(2**31) <= priority < 2**31:
        raise PolicyPackageError(f"{rule_id}.priority is outside int32 range")
    effective_from = _required_string(raw["effective_from"], f"{rule_id}.effective_from")
    effective_to_raw = raw["effective_to"]
    effective_to = (
        None
        if effective_to_raw is None
        else _required_string(effective_to_raw, f"{rule_id}.effective_to")
    )
    start = _parse_timestamp(effective_from, f"{rule_id}.effective_from")
    end = _parse_timestamp(effective_to, f"{rule_id}.effective_to") if effective_to is not None else None
    if end is not None and end < start:
        raise PolicyPackageError(f"{rule_id}: effective_to precedes effective_from")
    source_id = _required_string(raw["source_id"], f"{rule_id}.source_id")
    if source_id not in source_registry:
        raise PolicyPackageError(f"{rule_id}: source_id={source_id!r} is not registered")
    source = source_registry[source_id]
    source_sha256 = hashlib.sha256(canonical_json(source).encode("utf-8")).hexdigest()
    specificity = (
        validate_expression(asset_selector)
        + validate_expression(party_selector)
        + (validate_expression(purpose_selector) if purpose_selector is not None else 0)
        + validate_expression(condition)
        + (1 if jurisdiction_id is not None else 0)
    )
    rule = PolicyRule(
        policy_rule_id=rule_id,
        policy_profile_id=profile_id,
        version=version,
        jurisdiction_id=jurisdiction_id,
        rule_kind=rule_kind,
        action=action,
        asset_selector=asset_selector,
        party_selector=party_selector,
        purpose_selector=purpose_selector,
        condition=condition,
        priority=priority,
        effective_from=effective_from,
        effective_to=effective_to,
        source_id=source_id,
        source_citation=str(source["citation"]),
        source_sha256=source_sha256,
        violation_type=violation_type,
        specificity=specificity,
        effective_from_value=start,
        effective_to_value=end,
    )
    validate_record(contract, "policy_rule", rule.as_record())
    return rule


def _expression(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise PolicyPackageError(f"{label} must be an expression object")
    try:
        validate_expression(raw)
    except PolicyLanguageError as exc:
        raise PolicyPackageError(f"{label}: {exc}") from exc
    return json.loads(canonical_json(raw))


def _rule_rank(rule: PolicyRule) -> tuple[int, int, str]:
    return (-rule.priority, -rule.specificity, rule.policy_rule_id)


def _violation_type(
    winner: PolicyRule,
    facts: Mapping[str, Any],
    expected_action: str,
) -> str:
    if winner.violation_type != "none":
        return winner.violation_type
    if expected_action == "deny":
        return (
            "cross_region_rule_breach"
            if bool(facts["derived.is_cross_region"])
            else "unauthorized_purpose"
        )
    if expected_action == "erase":
        return "missing_erasure_propagation"
    if expected_action == "retain":
        return "premature_deletion"
    if expected_action == "notify":
        return "observer_omission"
    if expected_action == "escalate":
        return "false_confirmation"
    return "unauthorized_purpose"


def _explanation_code(winner: PolicyRule) -> str:
    normalized_rule_id = re.sub(r"[^A-Z0-9]+", "_", winner.policy_rule_id.upper()).strip("_")
    return f"POLICY_{winner.action.upper()}_{winner.rule_kind.upper()}_{normalized_rule_id}"


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise PolicyPackageError(f"cannot locate repository root from {start}")


def _parse_timestamp(value: str | None, label: str) -> datetime:
    if value is None:
        raise PolicyPackageError(f"{label}: timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyPackageError(f"{label}: invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PolicyPackageError(f"{label}: timestamp must include a UTC offset")
    if parsed.utcoffset().total_seconds() != 0:
        raise PolicyPackageError(f"{label}: timestamp must be normalized to UTC")
    return parsed


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyPackageError(f"{label} must be a non-empty string")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise PolicyPackageError(
            f"{label} keys must be {sorted(expected)}, got {sorted(actual)}"
        )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyPackageError(message)
