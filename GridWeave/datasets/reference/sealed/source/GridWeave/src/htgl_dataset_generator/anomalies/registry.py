"""Strict, digest-pinned anomaly invariant registry and edit grammar."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract


INVARIANT_BUNDLE_FORMAT = "htgl.anomaly.invariant-registry.v1"
GRAMMAR_BUNDLE_FORMAT = "htgl.anomaly.edit-grammar.v1"
DEFAULT_INVARIANT_PATH = Path("anomalies") / "invariant_registry_v1.json"
DEFAULT_GRAMMAR_PATH = Path("anomalies") / "edit_grammar_v1.json"
REQUIRED_DOMAINS = frozenset(
    {"schema", "physical", "workflow", "policy", "evidence", "observer", "causal", "temporal", "sampling", "pair"}
)


class AnomalyRegistryError(ValueError):
    """Raised when anomaly registries are incomplete, ambiguous, or unpinned."""


@dataclass(frozen=True)
class InvariantDefinition:
    invariant_id: str
    domain: str
    description: str
    applicability: str


@dataclass(frozen=True)
class InvariantRegistry:
    registry_id: str
    version: str
    acceptance_profile_id: str
    target_invariants: Mapping[str, str]
    invariants: tuple[InvariantDefinition, ...]
    bundle_sha256: str

    def invariant(self, invariant_id: str) -> InvariantDefinition:
        for item in self.invariants:
            if item.invariant_id == invariant_id:
                return item
        raise AnomalyRegistryError(f"unknown invariant_id={invariant_id!r}")


@dataclass(frozen=True)
class EditGrammarRule:
    anomaly_type: str
    target_invariant_id: str
    operations: tuple[str, ...]
    primitive_edit_cost: int
    severity: float
    protected_invariant_ids: tuple[str, ...]


@dataclass(frozen=True)
class EditGrammar:
    grammar_id: str
    version: str
    cost_model_id: str
    cost_model_version: str
    aggregation: str
    minimality_scope: str
    baseline_profile_ids: tuple[str, ...]
    rules: tuple[EditGrammarRule, ...]
    bundle_sha256: str

    def rule(self, anomaly_type: str) -> EditGrammarRule:
        for item in self.rules:
            if item.anomaly_type == anomaly_type:
                return item
        raise AnomalyRegistryError(f"no edit grammar rule for anomaly_type={anomaly_type!r}")


def load_anomaly_contract(
    resolved: ResolvedConfig,
    invariant_path: Path | None = None,
    grammar_path: Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> tuple[InvariantRegistry, EditGrammar]:
    """Load and cross-validate the exact configured invariant and edit bundles."""

    schema_contract = contract if contract is not None else load_contract()
    root = _repo_root()
    registry_raw = _load_json(
        invariant_path.resolve() if invariant_path is not None else root / DEFAULT_INVARIANT_PATH,
        "invariant registry",
    )
    grammar_raw = _load_json(
        grammar_path.resolve() if grammar_path is not None else root / DEFAULT_GRAMMAR_PATH,
        "edit grammar",
    )
    registry = _load_registry(registry_raw, resolved, schema_contract)
    grammar = _load_grammar(grammar_raw, resolved, schema_contract, registry)
    return registry, grammar


def _load_registry(raw: Mapping[str, Any], resolved: ResolvedConfig, contract: ContractSpec) -> InvariantRegistry:
    _exact_keys(
        raw,
        {"bundle_format", "registry_id", "version", "acceptance_profile_id", "target_invariants", "invariants"},
        "invariant registry",
    )
    _require(raw["bundle_format"] == INVARIANT_BUNDLE_FORMAT, "invariant bundle_format mismatch")
    _require(raw["registry_id"] == resolved.anomaly.invariant_registry_id, "invariant registry_id does not match config")
    _require(raw["version"] == resolved.anomaly.invariant_registry_version, "invariant registry version does not match config")
    _require(raw["acceptance_profile_id"] == resolved.anomaly.acceptance_profile_id, "acceptance profile does not match config")
    raw_targets = raw["target_invariants"]
    if not isinstance(raw_targets, Mapping):
        raise AnomalyRegistryError("target_invariants must be an object")
    contract_types = set(contract.dictionary_values("anomaly_type"))
    _require(set(raw_targets) == contract_types, "target_invariants must cover every locked anomaly type")
    target_invariants = {
        _string(key, "target anomaly type"): _string(value, f"target_invariants.{key}")
        for key, value in raw_targets.items()
    }
    raw_invariants = raw["invariants"]
    if not isinstance(raw_invariants, list) or not raw_invariants:
        raise AnomalyRegistryError("invariants must be a non-empty list")
    invariants = tuple(_load_invariant(item, index) for index, item in enumerate(raw_invariants))
    _unique((item.invariant_id for item in invariants), "invariant IDs")
    invariant_ids = {item.invariant_id for item in invariants}
    _require(set(target_invariants.values()) == set(resolved.anomaly.target_invariant_ids), "target invariant IDs do not match config")
    _require(set(target_invariants.values()) <= invariant_ids, "target invariant IDs are missing from registry")
    _require(set(resolved.anomaly.protected_invariant_ids) <= invariant_ids, "configured protected invariant IDs are missing")
    domains = {item.domain for item in invariants}
    _require(REQUIRED_DOMAINS <= domains, f"invariant registry is missing domains {sorted(REQUIRED_DOMAINS-domains)}")
    bundle_sha256 = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    _require(
        bundle_sha256 == resolved.anomaly.invariant_registry_sha256,
        "invariant registry SHA-256 does not match config: "
        f"expected={resolved.anomaly.invariant_registry_sha256} observed={bundle_sha256}",
    )
    return InvariantRegistry(
        registry_id=str(raw["registry_id"]),
        version=str(raw["version"]),
        acceptance_profile_id=str(raw["acceptance_profile_id"]),
        target_invariants=dict(sorted(target_invariants.items())),
        invariants=tuple(sorted(invariants, key=lambda item: item.invariant_id)),
        bundle_sha256=bundle_sha256,
    )


def _load_grammar(
    raw: Mapping[str, Any],
    resolved: ResolvedConfig,
    contract: ContractSpec,
    registry: InvariantRegistry,
) -> EditGrammar:
    _exact_keys(raw, {"bundle_format", "grammar_id", "version", "cost_model", "baseline_profile_ids", "rules"}, "edit grammar")
    _require(raw["bundle_format"] == GRAMMAR_BUNDLE_FORMAT, "edit grammar bundle_format mismatch")
    _require(raw["grammar_id"] == resolved.anomaly.edit_grammar_id, "edit grammar_id does not match config")
    _require(raw["version"] == resolved.anomaly.edit_grammar_version, "edit grammar version does not match config")
    cost = raw["cost_model"]
    if not isinstance(cost, Mapping):
        raise AnomalyRegistryError("cost_model must be an object")
    _exact_keys(cost, {"cost_model_id", "version", "aggregation", "minimality_scope"}, "cost_model")
    _require(cost["cost_model_id"] == resolved.anomaly.cost_model_id, "cost model ID does not match config")
    _require(cost["version"] == resolved.anomaly.cost_model_version, "cost model version does not match config")
    _require(cost["aggregation"] == "sum_primitive_edit_costs", "unsupported edit cost aggregation")
    baselines = _string_tuple(raw["baseline_profile_ids"], "baseline_profile_ids", non_empty=True)
    _require(baselines == resolved.anomaly.baseline_profile_ids, "baseline profiles do not match config")
    raw_rules = raw["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise AnomalyRegistryError("edit grammar rules must be a non-empty list")
    invariant_ids = {item.invariant_id for item in registry.invariants}
    rules = tuple(_load_rule(item, index, invariant_ids) for index, item in enumerate(raw_rules))
    _unique((item.anomaly_type for item in rules), "edit grammar anomaly types")
    _require(
        {item.anomaly_type for item in rules} == set(contract.dictionary_values("anomaly_type")),
        "edit grammar must cover every locked anomaly type",
    )
    for rule in rules:
        _require(
            registry.target_invariants[rule.anomaly_type] == rule.target_invariant_id,
            f"{rule.anomaly_type}: grammar target does not match invariant registry",
        )
        _require(rule.target_invariant_id not in rule.protected_invariant_ids, f"{rule.anomaly_type}: target cannot be protected")
    bundle_sha256 = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    _require(
        bundle_sha256 == resolved.anomaly.edit_grammar_sha256,
        "edit grammar SHA-256 does not match config: "
        f"expected={resolved.anomaly.edit_grammar_sha256} observed={bundle_sha256}",
    )
    return EditGrammar(
        grammar_id=str(raw["grammar_id"]),
        version=str(raw["version"]),
        cost_model_id=str(cost["cost_model_id"]),
        cost_model_version=str(cost["version"]),
        aggregation=str(cost["aggregation"]),
        minimality_scope=str(cost["minimality_scope"]),
        baseline_profile_ids=baselines,
        rules=tuple(sorted(rules, key=lambda item: item.anomaly_type)),
        bundle_sha256=bundle_sha256,
    )


def _load_invariant(raw: Any, index: int) -> InvariantDefinition:
    if not isinstance(raw, Mapping):
        raise AnomalyRegistryError(f"invariants[{index}] must be an object")
    _exact_keys(raw, {"invariant_id", "domain", "description", "applicability"}, f"invariants[{index}]")
    domain = _string(raw["domain"], f"invariants[{index}].domain")
    _require(domain in REQUIRED_DOMAINS, f"invariants[{index}]: unknown domain={domain!r}")
    return InvariantDefinition(
        invariant_id=_string(raw["invariant_id"], f"invariants[{index}].invariant_id"),
        domain=domain,
        description=_string(raw["description"], f"invariants[{index}].description"),
        applicability=_string(raw["applicability"], f"invariants[{index}].applicability"),
    )


def _load_rule(raw: Any, index: int, invariant_ids: set[str]) -> EditGrammarRule:
    if not isinstance(raw, Mapping):
        raise AnomalyRegistryError(f"rules[{index}] must be an object")
    _exact_keys(
        raw,
        {"anomaly_type", "target_invariant_id", "operations", "primitive_edit_cost", "severity", "protected_invariant_ids"},
        f"rules[{index}]",
    )
    target = _string(raw["target_invariant_id"], f"rules[{index}].target_invariant_id")
    protected = _string_tuple(raw["protected_invariant_ids"], f"rules[{index}].protected_invariant_ids", non_empty=True)
    _require(target in invariant_ids, f"rules[{index}]: target invariant is unknown")
    _require(set(protected) <= invariant_ids, f"rules[{index}]: protected invariant is unknown")
    cost = raw["primitive_edit_cost"]
    if not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0:
        raise AnomalyRegistryError(f"rules[{index}].primitive_edit_cost must be a positive integer")
    severity = raw["severity"]
    if isinstance(severity, bool) or not isinstance(severity, (int, float)) or not 0.0 <= float(severity) <= 1.0:
        raise AnomalyRegistryError(f"rules[{index}].severity must be in [0,1]")
    return EditGrammarRule(
        anomaly_type=_string(raw["anomaly_type"], f"rules[{index}].anomaly_type"),
        target_invariant_id=target,
        operations=_string_tuple(raw["operations"], f"rules[{index}].operations", non_empty=True),
        primitive_edit_cost=cost,
        severity=float(severity),
        protected_invariant_ids=tuple(sorted(protected)),
    )


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise AnomalyRegistryError(f"cannot locate repository root from {start}")


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AnomalyRegistryError(f"{label} not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AnomalyRegistryError(f"invalid {label} JSON {path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise AnomalyRegistryError(f"{label} root must be an object")
    return raw


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AnomalyRegistryError(f"{label} keys must be {sorted(expected)}, got {sorted(value)}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AnomalyRegistryError(f"{label} must be a non-empty string")
    return value


def _string_tuple(value: Any, label: str, *, non_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (non_empty and not value):
        raise AnomalyRegistryError(f"{label} must be a {'non-empty ' if non_empty else ''}list")
    result = tuple(_string(item, f"{label}[]") for item in value)
    _unique(result, label)
    return result


def _unique(values: Any, label: str) -> None:
    items = tuple(values)
    if len(set(items)) != len(items):
        raise AnomalyRegistryError(f"{label} contain duplicates")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AnomalyRegistryError(message)
