"""Safe declarative policy-condition language.

Expressions are JSON objects interpreted by a closed operator registry. This
module never executes source text, imports callables from policy packages, or
uses Python expression evaluation.
"""

from __future__ import annotations

from datetime import datetime
import json
from math import isfinite
from types import MappingProxyType
from typing import Any, Mapping


MAX_EXPRESSION_DEPTH = 16
MAX_EXPRESSION_NODES = 128
POLICY_ACTIONS = frozenset({"allow", "deny", "retain", "erase", "notify", "escalate", "no_op"})

SCALAR_FACT_FIELDS = frozenset(
    {
        "event.id",
        "event.type",
        "event.family",
        "event.timestamp",
        "workflow.type",
        "workflow.state_before",
        "workflow.state_after",
        "actor.source.id",
        "actor.source.class",
        "actor.source.region",
        "actor.source.jurisdiction",
        "actor.destination.id",
        "actor.destination.class",
        "actor.destination.region",
        "actor.destination.jurisdiction",
        "actor.requesting.id",
        "actor.requesting.class",
        "actor.controller.id",
        "actor.controller.class",
        "actor.processor.id",
        "actor.processor.class",
        "actor.oversight.id",
        "actor.oversight.class",
        "object.id",
        "object.type",
        "object.sensitivity",
        "purpose.id",
        "database.id",
        "database.region",
        "replica.count",
        "replica.non_exempt_count",
        "replica.pending_deletion_count",
        "state.consent",
        "state.retention",
        "state.erasure",
        "retention.has_exception",
        "observed.action",
        "derived.is_cross_region",
        "derived.is_cross_jurisdiction",
        "derived.data_location_cross_region",
        "fact.unknown_count",
    }
)
COLLECTION_FACT_FIELDS = frozenset(
    {
        "relationship.source_to_destination",
        "relationship.destination_to_source",
        "relationship.requesting_to_controller",
        "relationship.controller_to_processor",
        "object.allowed_purpose_ids",
        "replica.regions",
        "replica.deletion_statuses",
        "replica.retention_basis_rule_ids",
        "scope.jurisdictions",
    }
)
FACT_FIELDS = SCALAR_FACT_FIELDS | COLLECTION_FACT_FIELDS
ESSENTIAL_FACT_FIELDS = (
    "event.timestamp",
    "actor.source.region",
    "actor.source.jurisdiction",
    "actor.destination.region",
    "actor.destination.jurisdiction",
    "object.type",
    "purpose.id",
)


class PolicyLanguageError(ValueError):
    """Raised when a policy expression or normalized fact set is invalid."""


def canonical_json(value: Any) -> str:
    """Return deterministic strict JSON for package fields and digests."""

    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PolicyLanguageError(f"value is not canonical-JSON serializable: {exc}") from exc


def normalize_policy_facts(values: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate facts and derive region/jurisdiction truth from actual fields."""

    unknown_fields = sorted(set(values) - FACT_FIELDS)
    if unknown_fields:
        raise PolicyLanguageError(f"unknown policy fact fields {unknown_fields}")
    normalized: dict[str, Any] = {}
    for field in sorted(SCALAR_FACT_FIELDS):
        if field.startswith("derived.") or field == "fact.unknown_count":
            continue
        value = values.get(field)
        if isinstance(value, (list, tuple, dict, set)):
            raise PolicyLanguageError(f"fact {field}: expected scalar or null")
        _validate_finite_number(value, f"fact {field}")
        normalized[field] = value
    for field in sorted(COLLECTION_FACT_FIELDS):
        raw_value = values.get(field, ())
        if raw_value is None:
            raw_value = ()
        if not isinstance(raw_value, (list, tuple, set, frozenset)):
            raise PolicyLanguageError(f"fact {field}: expected a collection")
        items: list[Any] = []
        for item in raw_value:
            if isinstance(item, (list, tuple, dict, set)):
                raise PolicyLanguageError(f"fact {field}: collection items must be scalar")
            _validate_finite_number(item, f"fact {field} collection item")
            items.append(item)
        normalized[field] = tuple(sorted(set(items), key=lambda item: (type(item).__name__, str(item))))

    event_id = normalized.get("event.id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise PolicyLanguageError("fact event.id is required")
    timestamp = normalized.get("event.timestamp")
    if not isinstance(timestamp, str):
        raise PolicyLanguageError("fact event.timestamp must be a UTC timestamp string")
    _parse_timestamp(timestamp, "event.timestamp")
    observed_action = normalized.get("observed.action")
    if observed_action not in POLICY_ACTIONS:
        raise PolicyLanguageError(f"fact observed.action={observed_action!r} is not a policy action")

    source_region = normalized.get("actor.source.region")
    destination_region = normalized.get("actor.destination.region")
    source_jurisdiction = normalized.get("actor.source.jurisdiction")
    destination_jurisdiction = normalized.get("actor.destination.jurisdiction")
    database_region = normalized.get("database.region")
    normalized["derived.is_cross_region"] = bool(
        source_region is not None
        and destination_region is not None
        and source_region != destination_region
    )
    normalized["derived.is_cross_jurisdiction"] = bool(
        source_jurisdiction is not None
        and destination_jurisdiction is not None
        and source_jurisdiction != destination_jurisdiction
    )
    normalized["derived.data_location_cross_region"] = bool(
        destination_region is not None
        and database_region is not None
        and destination_region != database_region
    )
    normalized["scope.jurisdictions"] = tuple(
        sorted(
            {
                value
                for value in (source_jurisdiction, destination_jurisdiction)
                if isinstance(value, str) and value
            }
        )
    )
    normalized["fact.unknown_count"] = sum(
        1 for field in ESSENTIAL_FACT_FIELDS if normalized.get(field) is None
    )
    return MappingProxyType(dict(sorted(normalized.items())))


def validate_expression(expression: Mapping[str, Any]) -> int:
    """Validate an expression and return its deterministic specificity score."""

    node_count = [0]
    specificity = _validate_node(expression, depth=0, node_count=node_count)
    if node_count[0] > MAX_EXPRESSION_NODES:
        raise PolicyLanguageError(
            f"expression has {node_count[0]} nodes; maximum is {MAX_EXPRESSION_NODES}"
        )
    return specificity


def evaluate_expression(expression: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Evaluate a validated expression against normalized facts."""

    validate_expression(expression)
    missing_fields = sorted(_referenced_fields(expression) - set(facts))
    if missing_fields:
        raise PolicyLanguageError(f"facts are missing referenced fields {missing_fields}")
    return _evaluate_node(expression, facts)


def evaluate_validated_expression(expression: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Evaluate a package-loader-validated expression without repeated validation."""

    return _evaluate_node(expression, facts)


def _validate_node(expression: Any, *, depth: int, node_count: list[int]) -> int:
    if depth > MAX_EXPRESSION_DEPTH:
        raise PolicyLanguageError(f"expression depth exceeds {MAX_EXPRESSION_DEPTH}")
    if not isinstance(expression, Mapping):
        raise PolicyLanguageError("each expression node must be an object")
    node_count[0] += 1
    operator = expression.get("op")
    if not isinstance(operator, str):
        raise PolicyLanguageError("expression node requires string op")

    if operator == "const":
        _require_keys(expression, {"op", "value"}, operator)
        if not isinstance(expression["value"], bool):
            raise PolicyLanguageError("const.value must be boolean")
        return 0
    if operator in {"all", "any"}:
        _require_keys(expression, {"op", "args"}, operator)
        args = expression["args"]
        if not isinstance(args, list) or not args:
            raise PolicyLanguageError(f"{operator}.args must be a non-empty list")
        return sum(
            _validate_node(item, depth=depth + 1, node_count=node_count) for item in args
        )
    if operator == "not":
        _require_keys(expression, {"op", "arg"}, operator)
        return _validate_node(expression["arg"], depth=depth + 1, node_count=node_count)
    if operator in {"eq", "ne"}:
        _require_keys(expression, {"op", "field", "value"}, operator)
        _validate_field(expression["field"])
        _validate_scalar(expression["value"], f"{operator}.value")
        return 1
    if operator in {"in", "not_in", "intersects"}:
        _require_keys(expression, {"op", "field", "values"}, operator)
        field = _validate_field(expression["field"])
        values = expression["values"]
        if not isinstance(values, list) or not values:
            raise PolicyLanguageError(f"{operator}.values must be a non-empty list")
        for value in values:
            _validate_scalar(value, f"{operator}.values")
        if operator == "intersects" and field not in COLLECTION_FACT_FIELDS:
            raise PolicyLanguageError("intersects requires a collection fact field")
        return 1
    if operator in {"contains", "not_contains"}:
        _require_keys(expression, {"op", "field", "value"}, operator)
        field = _validate_field(expression["field"])
        if field not in COLLECTION_FACT_FIELDS:
            raise PolicyLanguageError(f"{operator} requires a collection fact field")
        _validate_scalar(expression["value"], f"{operator}.value")
        return 1
    if operator in {"contains_field", "not_contains_field"}:
        _require_keys(expression, {"op", "field", "other_field"}, operator)
        field = _validate_field(expression["field"])
        other_field = _validate_field(expression["other_field"])
        if field not in COLLECTION_FACT_FIELDS or other_field not in SCALAR_FACT_FIELDS:
            raise PolicyLanguageError(
                f"{operator} requires collection field and scalar other_field"
            )
        return 1
    if operator in {"is_null", "not_null"}:
        _require_keys(expression, {"op", "field"}, operator)
        _validate_field(expression["field"])
        return 1
    raise PolicyLanguageError(f"unsupported expression operator {operator!r}")


def _evaluate_node(expression: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    operator = str(expression["op"])
    if operator == "const":
        return bool(expression["value"])
    if operator == "all":
        return all(_evaluate_node(item, facts) for item in expression["args"])
    if operator == "any":
        return any(_evaluate_node(item, facts) for item in expression["args"])
    if operator == "not":
        return not _evaluate_node(expression["arg"], facts)
    field_value = facts[str(expression.get("field"))]
    if operator == "eq":
        return field_value == expression["value"]
    if operator == "ne":
        return field_value != expression["value"]
    if operator == "in":
        return field_value in expression["values"]
    if operator == "not_in":
        return field_value not in expression["values"]
    if operator == "intersects":
        return bool(set(field_value) & set(expression["values"]))
    if operator == "contains":
        return expression["value"] in field_value
    if operator == "not_contains":
        return expression["value"] not in field_value
    if operator == "contains_field":
        return facts[str(expression["other_field"])] in field_value
    if operator == "not_contains_field":
        return facts[str(expression["other_field"])] not in field_value
    if operator == "is_null":
        return field_value is None
    if operator == "not_null":
        return field_value is not None
    raise PolicyLanguageError(f"unsupported expression operator {operator!r}")


def _referenced_fields(expression: Mapping[str, Any]) -> set[str]:
    fields: set[str] = set()
    field = expression.get("field")
    other_field = expression.get("other_field")
    if isinstance(field, str):
        fields.add(field)
    if isinstance(other_field, str):
        fields.add(other_field)
    for key in ("args",):
        children = expression.get(key)
        if isinstance(children, list):
            for child in children:
                fields.update(_referenced_fields(child))
    child = expression.get("arg")
    if isinstance(child, Mapping):
        fields.update(_referenced_fields(child))
    return fields


def _require_keys(expression: Mapping[str, Any], expected: set[str], operator: str) -> None:
    actual = set(expression)
    if actual != expected:
        raise PolicyLanguageError(
            f"{operator} node keys must be {sorted(expected)}, got {sorted(actual)}"
        )


def _validate_field(value: Any) -> str:
    if not isinstance(value, str) or value not in FACT_FIELDS:
        raise PolicyLanguageError(f"unknown policy fact field {value!r}")
    return value


def _validate_scalar(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise PolicyLanguageError(f"{label} must be a JSON scalar or null")
    _validate_finite_number(value, label)


def _validate_finite_number(value: Any, label: str) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise PolicyLanguageError(f"{label} must be finite")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyLanguageError(f"{label}: invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PolicyLanguageError(f"{label}: timestamp must include a UTC offset")
    if parsed.utcoffset().total_seconds() != 0:
        raise PolicyLanguageError(f"{label}: timestamp must be normalized to UTC")
    return parsed
