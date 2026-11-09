"""Strict versioned policy-to-evidence obligation template bundle."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.policy import PolicyPackage
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract


BUNDLE_FORMAT = "htgl.evidence.obligation-templates.v1"
DEFAULT_BUNDLE_RELATIVE_PATH = Path("evidence") / "obligation_templates_v1.json"
EXPANSION_MODES = frozenset(
    {
        "object",
        "non_exempt_replicas",
        "exempt_replicas",
        "workflow_events",
        "actor_set",
        "causal_closure",
    }
)
RESPONSIBLE_ACTOR_ROLES = frozenset(
    {
        "source",
        "requesting",
        "controller",
        "processor",
        "oversight",
        "replica_operator",
        "coverage_actor",
    }
)
EVENT_ACTOR_ROLES = frozenset({"source", "requesting", "controller", "processor", "oversight"})
MINIMUM_COUNT_MODES = frozenset({"fixed", "coverage_size"})
SCOPE_BY_EXPANSION = {
    "object": "object",
    "non_exempt_replicas": "replica_set",
    "exempt_replicas": "replica_set",
    "workflow_events": "workflow",
    "actor_set": "actor_set",
    "causal_closure": "causal_closure",
}


class ObligationTemplateError(ValueError):
    """Raised when the configured obligation grammar is incomplete or invalid."""


@dataclass(frozen=True)
class ObligationClause:
    template_id: str
    clause_id: str
    policy_rule_ids: tuple[str, ...]
    workflow_types: tuple[str, ...]
    event_types: tuple[str, ...]
    obligation_type: str
    coverage_scope: str
    expansion_mode: str
    actor_roles: tuple[str, ...]
    responsible_actor_role: str
    deadline_seconds: int
    required_evidence_types: tuple[str, ...]
    minimum_count_mode: str
    fixed_minimum_count: int
    requires_evidence_trigger: bool


@dataclass(frozen=True)
class ObligationTemplate:
    template_id: str
    version: str
    clauses: tuple[ObligationClause, ...]


@dataclass(frozen=True)
class ObligationTemplateBundle:
    bundle_format: str
    bundle_id: str
    version: str
    sufficiency_profile_id: str
    proof_limit_statement: str
    bundle_sha256: str
    templates: tuple[ObligationTemplate, ...]

    @property
    def clauses(self) -> tuple[ObligationClause, ...]:
        return tuple(
            sorted(
                (clause for template in self.templates for clause in template.clauses),
                key=lambda clause: (clause.template_id, clause.clause_id),
            )
        )


def load_obligation_template_bundle(
    resolved: ResolvedConfig,
    policy_package: PolicyPackage,
    path: Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> ObligationTemplateBundle:
    """Load the exact configured obligation grammar and validate all references."""

    schema_contract = contract if contract is not None else load_contract()
    bundle_path = path.resolve() if path is not None else _repo_root() / DEFAULT_BUNDLE_RELATIVE_PATH
    try:
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ObligationTemplateError(f"obligation template bundle not found: {bundle_path}") from exc
    except json.JSONDecodeError as exc:
        raise ObligationTemplateError(f"invalid obligation template JSON {bundle_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ObligationTemplateError("obligation template bundle root must be an object")
    _exact_keys(
        raw,
        {
            "bundle_format",
            "bundle_id",
            "version",
            "sufficiency_profile_id",
            "proof_limit_statement",
            "templates",
        },
        "obligation template bundle",
    )
    _require(raw["bundle_format"] == BUNDLE_FORMAT, f"bundle_format must be {BUNDLE_FORMAT}")
    _require(raw["bundle_id"] == resolved.evidence.obligation_template_bundle_id, "bundle_id does not match config")
    _require(raw["version"] == resolved.evidence.obligation_template_bundle_version, "bundle version does not match config")
    _require(
        raw["sufficiency_profile_id"] == resolved.evidence.sufficiency_profile_id,
        "sufficiency profile does not match config",
    )
    _require(
        raw["proof_limit_statement"] == resolved.evidence.proof_limit_statement,
        "proof limit statement does not match config",
    )
    raw_templates = raw["templates"]
    if not isinstance(raw_templates, list) or not raw_templates:
        raise ObligationTemplateError("templates must be a non-empty list")
    templates = tuple(
        _load_template(item, schema_contract, policy_package, resolved, index)
        for index, item in enumerate(raw_templates)
    )
    template_ids = tuple(template.template_id for template in templates)
    if len(set(template_ids)) != len(template_ids):
        raise ObligationTemplateError("duplicate obligation template IDs")
    if set(template_ids) != set(resolved.evidence.obligation_template_ids):
        raise ObligationTemplateError(
            "bundle templates must exactly match configured obligation_template_ids: "
            f"configured={sorted(resolved.evidence.obligation_template_ids)} bundle={sorted(template_ids)}"
        )
    bundle_sha256 = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    if bundle_sha256 != resolved.evidence.obligation_template_bundle_sha256:
        raise ObligationTemplateError(
            "obligation template bundle SHA-256 does not match resolved config: "
            f"expected={resolved.evidence.obligation_template_bundle_sha256} observed={bundle_sha256}"
        )
    bundle = ObligationTemplateBundle(
        bundle_format=str(raw["bundle_format"]),
        bundle_id=str(raw["bundle_id"]),
        version=str(raw["version"]),
        sufficiency_profile_id=str(raw["sufficiency_profile_id"]),
        proof_limit_statement=str(raw["proof_limit_statement"]),
        bundle_sha256=bundle_sha256,
        templates=tuple(sorted(templates, key=lambda template: template.template_id)),
    )
    _validate_bundle_semantics(bundle)
    return bundle


def _load_template(
    raw: Any,
    contract: ContractSpec,
    policy_package: PolicyPackage,
    resolved: ResolvedConfig,
    index: int,
) -> ObligationTemplate:
    if not isinstance(raw, Mapping):
        raise ObligationTemplateError(f"templates[{index}] must be an object")
    _exact_keys(raw, {"template_id", "version", "clauses"}, f"templates[{index}]")
    template_id = _string(raw["template_id"], f"templates[{index}].template_id")
    version = _string(raw["version"], f"{template_id}.version")
    raw_clauses = raw["clauses"]
    if not isinstance(raw_clauses, list) or not raw_clauses:
        raise ObligationTemplateError(f"{template_id}.clauses must be a non-empty list")
    clauses = tuple(
        _load_clause(item, template_id, contract, policy_package, resolved, clause_index)
        for clause_index, item in enumerate(raw_clauses)
    )
    clause_ids = [clause.clause_id for clause in clauses]
    if len(set(clause_ids)) != len(clause_ids):
        raise ObligationTemplateError(f"{template_id}: duplicate clause IDs")
    return ObligationTemplate(template_id, version, tuple(sorted(clauses, key=lambda clause: clause.clause_id)))


def _load_clause(
    raw: Any,
    template_id: str,
    contract: ContractSpec,
    policy_package: PolicyPackage,
    resolved: ResolvedConfig,
    index: int,
) -> ObligationClause:
    if not isinstance(raw, Mapping):
        raise ObligationTemplateError(f"{template_id}.clauses[{index}] must be an object")
    expected_keys = {
        "clause_id",
        "policy_rule_ids",
        "workflow_types",
        "event_types",
        "obligation_type",
        "coverage_scope",
        "expansion_mode",
        "actor_roles",
        "responsible_actor_role",
        "deadline_seconds",
        "required_evidence_types",
        "minimum_count_mode",
        "fixed_minimum_count",
        "requires_evidence_trigger",
    }
    _exact_keys(raw, expected_keys, f"{template_id}.clauses[{index}]")
    clause_id = _string(raw["clause_id"], f"{template_id}.clauses[{index}].clause_id")
    policy_rule_ids = _string_tuple(raw["policy_rule_ids"], f"{clause_id}.policy_rule_ids", non_empty=True)
    package_rule_ids = {rule.policy_rule_id for rule in policy_package.rules}
    unknown_rules = sorted(set(policy_rule_ids) - package_rule_ids)
    if unknown_rules:
        raise ObligationTemplateError(f"{clause_id}: unknown policy rules {unknown_rules}")
    workflow_types = _string_tuple(raw["workflow_types"], f"{clause_id}.workflow_types", non_empty=False)
    event_types = _string_tuple(raw["event_types"], f"{clause_id}.event_types", non_empty=False)
    _enum_values(workflow_types, contract.dictionary_values("workflow_type"), f"{clause_id}.workflow_types")
    _enum_values(event_types, contract.dictionary_values("event_type"), f"{clause_id}.event_types")
    obligation_type = _string(raw["obligation_type"], f"{clause_id}.obligation_type")
    _enum_values((obligation_type,), contract.dictionary_values("obligation_type"), f"{clause_id}.obligation_type")
    coverage_scope = _string(raw["coverage_scope"], f"{clause_id}.coverage_scope")
    _enum_values((coverage_scope,), contract.dictionary_values("coverage_scope"), f"{clause_id}.coverage_scope")
    expansion_mode = _string(raw["expansion_mode"], f"{clause_id}.expansion_mode")
    _require(expansion_mode in EXPANSION_MODES, f"{clause_id}: unknown expansion_mode={expansion_mode!r}")
    _require(
        SCOPE_BY_EXPANSION[expansion_mode] == coverage_scope,
        f"{clause_id}: coverage_scope={coverage_scope!r} is incompatible with expansion_mode={expansion_mode!r}",
    )
    actor_roles = _string_tuple(raw["actor_roles"], f"{clause_id}.actor_roles", non_empty=False)
    _enum_values(actor_roles, EVENT_ACTOR_ROLES, f"{clause_id}.actor_roles")
    responsible_actor_role = _string(raw["responsible_actor_role"], f"{clause_id}.responsible_actor_role")
    _require(
        responsible_actor_role in RESPONSIBLE_ACTOR_ROLES,
        f"{clause_id}: unknown responsible_actor_role={responsible_actor_role!r}",
    )
    if expansion_mode == "actor_set":
        _require(bool(actor_roles), f"{clause_id}: actor_set expansion requires actor_roles")
        _require(responsible_actor_role == "coverage_actor", f"{clause_id}: actor_set requires coverage_actor")
    else:
        _require(not actor_roles, f"{clause_id}: actor_roles are valid only for actor_set expansion")
        _require(responsible_actor_role != "coverage_actor", f"{clause_id}: coverage_actor requires actor_set")
    if expansion_mode in {"non_exempt_replicas", "exempt_replicas"}:
        _require(responsible_actor_role == "replica_operator", f"{clause_id}: replica expansion requires replica_operator")
    deadline_seconds = _positive_int(raw["deadline_seconds"], f"{clause_id}.deadline_seconds")
    evidence_types = _string_tuple(
        raw["required_evidence_types"], f"{clause_id}.required_evidence_types", non_empty=True
    )
    _enum_values(evidence_types, contract.dictionary_values("evidence_type"), f"{clause_id}.required_evidence_types")
    unconfigured_types = sorted(set(evidence_types) - set(resolved.evidence.receipt_profiles))
    if unconfigured_types:
        raise ObligationTemplateError(f"{clause_id}: evidence types not enabled by config {unconfigured_types}")
    minimum_count_mode = _string(raw["minimum_count_mode"], f"{clause_id}.minimum_count_mode")
    _require(minimum_count_mode in MINIMUM_COUNT_MODES, f"{clause_id}: unknown minimum_count_mode")
    fixed_minimum_count = _positive_int(raw["fixed_minimum_count"], f"{clause_id}.fixed_minimum_count")
    requires_evidence_trigger = raw["requires_evidence_trigger"]
    if not isinstance(requires_evidence_trigger, bool):
        raise ObligationTemplateError(f"{clause_id}.requires_evidence_trigger must be boolean")
    return ObligationClause(
        template_id=template_id,
        clause_id=clause_id,
        policy_rule_ids=tuple(sorted(policy_rule_ids)),
        workflow_types=tuple(sorted(workflow_types)),
        event_types=tuple(sorted(event_types)),
        obligation_type=obligation_type,
        coverage_scope=coverage_scope,
        expansion_mode=expansion_mode,
        actor_roles=tuple(sorted(actor_roles)),
        responsible_actor_role=responsible_actor_role,
        deadline_seconds=deadline_seconds,
        required_evidence_types=tuple(sorted(evidence_types)),
        minimum_count_mode=minimum_count_mode,
        fixed_minimum_count=fixed_minimum_count,
        requires_evidence_trigger=requires_evidence_trigger,
    )


def _validate_bundle_semantics(bundle: ObligationTemplateBundle) -> None:
    clauses = bundle.clauses
    scopes = {clause.coverage_scope for clause in clauses}
    missing_scopes = sorted(set(SCOPE_BY_EXPANSION.values()) - scopes)
    if missing_scopes:
        raise ObligationTemplateError(f"obligation bundle does not cover scopes {missing_scopes}")
    required_erasure_semantics = {
        ("erasure_requested", "authorization", "object", "object"),
        ("erasure_requested", "provenance", "object", "object"),
        ("erasure_propagated", "provenance", "replica_set", "non_exempt_replicas"),
        ("erasure_executed", "replica_deletion", "replica_set", "non_exempt_replicas"),
        ("erasure_requested", "retention_exception", "replica_set", "exempt_replicas"),
        ("erasure_verified", "verification", "causal_closure", "causal_closure"),
    }
    observed = {
        (event_type, clause.obligation_type, clause.coverage_scope, clause.expansion_mode)
        for clause in clauses
        for event_type in clause.event_types
        if "erasure" in clause.workflow_types
    }
    missing = sorted(required_erasure_semantics - observed)
    if missing:
        raise ObligationTemplateError(f"obligation bundle is missing erasure semantics {missing}")


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise ObligationTemplateError(f"cannot locate repository root from {start}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ObligationTemplateError(f"{label} keys must be {sorted(expected)}, got {sorted(value)}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ObligationTemplateError(f"{label} must be a non-empty string")
    return value


def _string_tuple(value: Any, label: str, *, non_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise ObligationTemplateError(f"{label} must be a {qualifier}list")
    items = tuple(_string(item, f"{label}[]") for item in value)
    if len(set(items)) != len(items):
        raise ObligationTemplateError(f"{label} contains duplicates")
    return items


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ObligationTemplateError(f"{label} must be a positive integer")
    if value >= 2**31:
        raise ObligationTemplateError(f"{label} exceeds int32")
    return value


def _enum_values(values: tuple[str, ...], allowed: tuple[str, ...] | frozenset[str], label: str) -> None:
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ObligationTemplateError(f"{label} contains unknown values {unknown}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ObligationTemplateError(message)
