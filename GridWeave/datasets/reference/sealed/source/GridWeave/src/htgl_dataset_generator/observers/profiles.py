"""Digest-pinned observer profile, leakage, collusion, and task contract."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .language import validate_visibility_expression


BUNDLE_FORMAT = "htgl.observer.profiles.v1"
DEFAULT_BUNDLE_PATH = Path("observers") / "observer_profiles_v1.json"
OBSERVER_MODES = frozenset(
    {"full", "role_based", "delayed", "lossy", "adversarial_omission", "collusion"}
)
PAYLOAD_FIELDS = frozenset(
    {
        "actor_classes",
        "causal_parent_refs",
        "database_kind",
        "event_family",
        "event_ref",
        "event_type",
        "evidence_present",
        "evidence_receipt_count",
        "evidence_types",
        "inferred_summary",
        "object_type",
        "policy_purpose_id",
        "workflow_ref",
        "workflow_state_after",
        "workflow_state_before",
    }
)
TASK_METRICS = frozenset(
    {"visible_edge_coverage", "evidence_recoverability", "anomaly_event_recoverability"}
)


class ObserverProfileError(ValueError):
    """Raised when the observer contract is incomplete, inconsistent, or unpinned."""


@dataclass(frozen=True)
class DelayProfile:
    profile_id: str
    minimum_seconds: int
    maximum_seconds: int
    clock_offset_seconds: int


@dataclass(frozen=True)
class LossProfile:
    profile_id: str
    probability: float


@dataclass(frozen=True)
class VisibilityRule:
    rule_id: str
    visibility_class: str
    condition: Mapping[str, Any]


@dataclass(frozen=True)
class ObserverProfile:
    profile_id: str
    mode: str
    observer_actor_class: str
    release_access_class: str
    schema_profile_id: str
    visibility_rules: tuple[VisibilityRule, ...]
    allowed_payload_fields: tuple[str, ...]
    redaction_profile_id: str
    delay_profile_id: str
    loss_profile_id: str
    adversarial_omission_probability: float
    adversarial_omission_condition: Mapping[str, Any]
    collusion_member_profile_ids: tuple[str, ...]


@dataclass(frozen=True)
class CollusionProfile:
    profile_id: str
    output_profile_id: str
    member_profile_ids: tuple[str, ...]
    composition: str
    threat_model: str


@dataclass(frozen=True)
class ObserverTask:
    task_id: str
    metric_name: str
    required_profile_thresholds: Mapping[str, float]


@dataclass(frozen=True)
class ObserverProfileBundle:
    bundle_id: str
    version: str
    visibility_dsl_profile_id: str
    leakage_scan_profile_id: str
    task_registry_id: str
    redaction_profiles: Mapping[str, tuple[str, ...]]
    delay_profiles: Mapping[str, DelayProfile]
    loss_profiles: Mapping[str, LossProfile]
    forbidden_field_sets: Mapping[str, tuple[str, ...]]
    profiles: tuple[ObserverProfile, ...]
    collusion_profiles: Mapping[str, CollusionProfile]
    tasks: tuple[ObserverTask, ...]
    bundle_sha256: str

    def profile(self, profile_id: str) -> ObserverProfile:
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise ObserverProfileError(f"unknown observer profile_id={profile_id!r}")


def load_observer_profile_bundle(
    resolved: ResolvedConfig,
    path: Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> ObserverProfileBundle:
    """Load and validate the exact configured S11 observer contract."""

    schema_contract = contract if contract is not None else load_contract()
    source = path.resolve() if path is not None else _repo_root() / DEFAULT_BUNDLE_PATH
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ObserverProfileError(f"observer profile bundle not found: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ObserverProfileError(f"invalid observer profile JSON {source}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ObserverProfileError("observer profile bundle root must be an object")
    _exact_keys(
        raw,
        {
            "bundle_format",
            "bundle_id",
            "version",
            "visibility_dsl_profile_id",
            "leakage_scan_profile_id",
            "task_registry_id",
            "redaction_profiles",
            "delay_profiles",
            "loss_profiles",
            "forbidden_field_sets",
            "profiles",
            "collusion_profiles",
            "tasks",
        },
        "observer profile bundle",
    )
    _require(raw["bundle_format"] == BUNDLE_FORMAT, f"bundle_format must be {BUNDLE_FORMAT}")
    _require(raw["bundle_id"] == resolved.observer.profile_bundle_id, "bundle_id does not match config")
    _require(raw["version"] == resolved.observer.profile_bundle_version, "bundle version does not match config")
    for key in ("visibility_dsl_profile_id", "leakage_scan_profile_id", "task_registry_id"):
        _require(raw[key] == getattr(resolved.observer, key), f"{key} does not match config")

    redactions = _string_list_mapping(raw["redaction_profiles"], "redaction_profiles")
    delays = _load_delays(raw["delay_profiles"])
    losses = _load_losses(raw["loss_profiles"])
    forbidden = _string_list_mapping(raw["forbidden_field_sets"], "forbidden_field_sets")
    profiles = tuple(_load_profile(item, index, schema_contract) for index, item in enumerate(_list(raw["profiles"], "profiles")))
    _unique((item.profile_id for item in profiles), "observer profile IDs")
    collusions = _load_collusions(raw["collusion_profiles"])
    tasks = tuple(_load_task(item, index) for index, item in enumerate(_list(raw["tasks"], "tasks")))
    _unique((item.task_id for item in tasks), "observer task IDs")

    profile_by_id = {item.profile_id: item for item in profiles}
    _require(tuple(item.profile_id for item in profiles) == resolved.observer.observer_profile_ids, "profile order/IDs do not match config")
    _require({item.mode for item in profiles} == OBSERVER_MODES, "profiles must cover all six observer modes")
    _require(set(redactions) == set(resolved.observer.redaction_profiles), "redaction profile IDs do not match config")
    _require(set(delays) == set(resolved.observer.delay_profiles), "delay profile IDs do not match config")
    _require(set(losses) == set(resolved.observer.loss_profiles), "loss profile IDs do not match config")
    _require(set(forbidden) == set(resolved.observer.forbidden_field_sets), "forbidden field sets do not match config")
    _require(set(collusions) == set(resolved.observer.collusion_profiles), "collusion profile IDs do not match config")
    for profile in profiles:
        _require(profile.redaction_profile_id in redactions, f"{profile.profile_id}: redaction profile missing")
        _require(profile.delay_profile_id in delays, f"{profile.profile_id}: delay profile missing")
        _require(profile.loss_profile_id in losses, f"{profile.profile_id}: loss profile missing")
        unknown_members = sorted(set(profile.collusion_member_profile_ids) - set(profile_by_id))
        _require(not unknown_members, f"{profile.profile_id}: unknown collusion members {unknown_members}")
        if profile.mode == "collusion":
            _require(len(profile.collusion_member_profile_ids) >= 2, f"{profile.profile_id}: collusion needs at least two members")
            _require(not profile.visibility_rules, f"{profile.profile_id}: collusion visibility derives from members")
        else:
            _require(not profile.collusion_member_profile_ids, f"{profile.profile_id}: only collusion mode may name members")
            _require(bool(profile.visibility_rules), f"{profile.profile_id}: visibility_rules must not be empty")
    _validate_collusion_graph(profile_by_id, collusions)
    for task in tasks:
        _require(set(task.required_profile_thresholds) <= set(profile_by_id), f"{task.task_id}: unknown required profile")

    digest = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    _require(
        digest == resolved.observer.profile_bundle_sha256,
        "observer profile bundle SHA-256 does not match resolved config: "
        f"expected={resolved.observer.profile_bundle_sha256} observed={digest}",
    )
    return ObserverProfileBundle(
        bundle_id=str(raw["bundle_id"]),
        version=str(raw["version"]),
        visibility_dsl_profile_id=str(raw["visibility_dsl_profile_id"]),
        leakage_scan_profile_id=str(raw["leakage_scan_profile_id"]),
        task_registry_id=str(raw["task_registry_id"]),
        redaction_profiles=dict(sorted(redactions.items())),
        delay_profiles=dict(sorted(delays.items())),
        loss_profiles=dict(sorted(losses.items())),
        forbidden_field_sets=dict(sorted(forbidden.items())),
        profiles=profiles,
        collusion_profiles=dict(sorted(collusions.items())),
        tasks=tuple(sorted(tasks, key=lambda item: item.task_id)),
        bundle_sha256=digest,
    )


def _load_profile(raw: Any, index: int, contract: ContractSpec) -> ObserverProfile:
    path = f"profiles[{index}]"
    value = _mapping(raw, path)
    _exact_keys(
        value,
        {
            "profile_id", "mode", "observer_actor_class", "release_access_class",
            "schema_profile_id", "visibility_rules", "allowed_payload_fields",
            "redaction_profile_id", "delay_profile_id", "loss_profile_id",
            "adversarial_omission_probability", "adversarial_omission_condition",
            "collusion_member_profile_ids",
        },
        path,
    )
    mode = _string(value["mode"], f"{path}.mode")
    _require(mode in OBSERVER_MODES, f"{path}.mode is unsupported")
    actor_class = _string(value["observer_actor_class"], f"{path}.observer_actor_class")
    _require(actor_class in contract.dictionary_values("actor_class"), f"{path}: unknown actor class")
    access = _string(value["release_access_class"], f"{path}.release_access_class")
    _require(access in contract.dictionary_values("privacy_class"), f"{path}: unknown access class")
    rules = tuple(_load_visibility_rule(item, path, rule_index, contract) for rule_index, item in enumerate(_list(value["visibility_rules"], f"{path}.visibility_rules", non_empty=False)))
    _unique((item.rule_id for item in rules), f"{path} rule IDs")
    fields = _strings(value["allowed_payload_fields"], f"{path}.allowed_payload_fields", non_empty=False)
    _require(set(fields) <= PAYLOAD_FIELDS, f"{path}: unknown allowed payload fields {sorted(set(fields)-PAYLOAD_FIELDS)}")
    probability = _float(value["adversarial_omission_probability"], f"{path}.adversarial_omission_probability")
    _require(0.0 <= probability <= 1.0, f"{path}: omission probability must be in [0,1]")
    condition = _mapping(value["adversarial_omission_condition"], f"{path}.adversarial_omission_condition")
    validate_visibility_expression(condition)
    if mode != "adversarial_omission":
        _require(probability == 0.0, f"{path}: only adversarial mode may have omission probability")
    return ObserverProfile(
        profile_id=_string(value["profile_id"], f"{path}.profile_id"),
        mode=mode,
        observer_actor_class=actor_class,
        release_access_class=access,
        schema_profile_id=_string(value["schema_profile_id"], f"{path}.schema_profile_id"),
        visibility_rules=rules,
        allowed_payload_fields=fields,
        redaction_profile_id=_string(value["redaction_profile_id"], f"{path}.redaction_profile_id"),
        delay_profile_id=_string(value["delay_profile_id"], f"{path}.delay_profile_id"),
        loss_profile_id=_string(value["loss_profile_id"], f"{path}.loss_profile_id"),
        adversarial_omission_probability=probability,
        adversarial_omission_condition=dict(condition),
        collusion_member_profile_ids=_strings(value["collusion_member_profile_ids"], f"{path}.collusion_member_profile_ids", non_empty=False),
    )


def _load_visibility_rule(raw: Any, profile_path: str, index: int, contract: ContractSpec) -> VisibilityRule:
    path = f"{profile_path}.visibility_rules[{index}]"
    value = _mapping(raw, path)
    _exact_keys(value, {"rule_id", "visibility_class", "condition"}, path)
    visibility_class = _string(value["visibility_class"], f"{path}.visibility_class")
    _require(visibility_class in contract.dictionary_values("visibility_class"), f"{path}: unknown visibility class")
    _require(visibility_class not in {"delayed", "omitted", "redacted"}, f"{path}: derived visibility class cannot be a base rule")
    condition = _mapping(value["condition"], f"{path}.condition")
    validate_visibility_expression(condition)
    return VisibilityRule(_string(value["rule_id"], f"{path}.rule_id"), visibility_class, dict(condition))


def _load_delays(raw: Any) -> Mapping[str, DelayProfile]:
    values = _mapping(raw, "delay_profiles")
    result: dict[str, DelayProfile] = {}
    for profile_id, item in values.items():
        value = _mapping(item, f"delay_profiles.{profile_id}")
        _exact_keys(value, {"minimum_seconds", "maximum_seconds", "clock_offset_seconds"}, f"delay_profiles.{profile_id}")
        minimum = _integer(value["minimum_seconds"], f"delay_profiles.{profile_id}.minimum_seconds")
        maximum = _integer(value["maximum_seconds"], f"delay_profiles.{profile_id}.maximum_seconds")
        offset = _integer(value["clock_offset_seconds"], f"delay_profiles.{profile_id}.clock_offset_seconds")
        _require(0 <= minimum <= maximum, f"delay_profiles.{profile_id}: invalid interval")
        result[_string(profile_id, "delay profile ID")] = DelayProfile(str(profile_id), minimum, maximum, offset)
    return result


def _load_losses(raw: Any) -> Mapping[str, LossProfile]:
    values = _mapping(raw, "loss_profiles")
    result: dict[str, LossProfile] = {}
    for profile_id, item in values.items():
        value = _mapping(item, f"loss_profiles.{profile_id}")
        _exact_keys(value, {"probability"}, f"loss_profiles.{profile_id}")
        probability = _float(value["probability"], f"loss_profiles.{profile_id}.probability")
        _require(0.0 <= probability <= 1.0, f"loss_profiles.{profile_id}: probability must be in [0,1]")
        result[_string(profile_id, "loss profile ID")] = LossProfile(str(profile_id), probability)
    return result


def _load_collusions(raw: Any) -> Mapping[str, CollusionProfile]:
    values = _mapping(raw, "collusion_profiles")
    result: dict[str, CollusionProfile] = {}
    for profile_id, item in values.items():
        path = f"collusion_profiles.{profile_id}"
        value = _mapping(item, path)
        _exact_keys(value, {"output_profile_id", "member_profile_ids", "composition", "threat_model"}, path)
        members = _strings(value["member_profile_ids"], f"{path}.member_profile_ids")
        _require(len(members) >= 2, f"{path}: at least two members required")
        result[str(profile_id)] = CollusionProfile(
            profile_id=str(profile_id),
            output_profile_id=_string(value["output_profile_id"], f"{path}.output_profile_id"),
            member_profile_ids=members,
            composition=_string(value["composition"], f"{path}.composition"),
            threat_model=_string(value["threat_model"], f"{path}.threat_model"),
        )
    return result


def _load_task(raw: Any, index: int) -> ObserverTask:
    path = f"tasks[{index}]"
    value = _mapping(raw, path)
    _exact_keys(value, {"task_id", "metric_name", "required_profile_thresholds"}, path)
    metric = _string(value["metric_name"], f"{path}.metric_name")
    _require(metric in TASK_METRICS, f"{path}: unsupported task metric")
    thresholds_raw = _mapping(value["required_profile_thresholds"], f"{path}.required_profile_thresholds")
    thresholds = {str(key): _float(item, f"{path}.required_profile_thresholds.{key}") for key, item in thresholds_raw.items()}
    _require(all(0.0 <= item <= 1.0 for item in thresholds.values()), f"{path}: thresholds must be in [0,1]")
    return ObserverTask(_string(value["task_id"], f"{path}.task_id"), metric, dict(sorted(thresholds.items())))


def _validate_collusion_graph(
    profiles: Mapping[str, ObserverProfile], collusions: Mapping[str, CollusionProfile]
) -> None:
    outputs = {item.output_profile_id: item for item in collusions.values()}
    _require(set(outputs) == {item.profile_id for item in profiles.values() if item.mode == "collusion"}, "collusion outputs do not match collusion-mode profiles")
    for output_id, item in outputs.items():
        profile = profiles[output_id]
        _require(profile.collusion_member_profile_ids == item.member_profile_ids, f"{output_id}: collusion members disagree")
        _require(item.composition == "union_earliest_visible_payload_union", f"{output_id}: unsupported composition")
        _require(bool(item.threat_model.strip()), f"{output_id}: threat model is empty")
        _require(output_id not in item.member_profile_ids, f"{output_id}: self-collusion cycle")
        _require(all(profiles[member].mode != "collusion" for member in item.member_profile_ids), f"{output_id}: nested collusion is not supported")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ObserverProfileError(f"{path}: expected object")
    return value


def _list(value: Any, path: str, *, non_empty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (non_empty and not value):
        raise ObserverProfileError(f"{path}: expected {'non-empty ' if non_empty else ''}list")
    return value


def _strings(value: Any, path: str, *, non_empty: bool = True) -> tuple[str, ...]:
    items = _list(value, path, non_empty=non_empty)
    result = tuple(_string(item, f"{path}[{index}]") for index, item in enumerate(items))
    _unique(result, path)
    return result


def _string_list_mapping(value: Any, path: str) -> Mapping[str, tuple[str, ...]]:
    raw = _mapping(value, path)
    return {str(key): _strings(item, f"{path}.{key}") for key, item in raw.items()}


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ObserverProfileError(f"{path}: expected non-empty string")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ObserverProfileError(f"{path}: expected integer")
    return value


def _float(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ObserverProfileError(f"{path}: expected number")
    return float(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    if set(value) != expected:
        raise ObserverProfileError(
            f"{path}: keys must be exactly {sorted(expected)}; observed={sorted(value)}"
        )


def _unique(values: Any, path: str) -> None:
    items = tuple(values)
    if len(items) != len(set(items)):
        raise ObserverProfileError(f"{path}: duplicate values")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ObserverProfileError(message)


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise ObserverProfileError(f"cannot locate contract and observer asset root from {start}")
