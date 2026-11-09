"""Safe declarative visibility language for frozen observer facts."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping


MAX_EXPRESSION_DEPTH = 12
MAX_EXPRESSION_NODES = 128
SCALAR_FACT_FIELDS = frozenset(
    {
        "anomaly.workflow_member",
        "event.database_region",
        "event.family",
        "event.id",
        "event.source_region",
        "event.type",
        "event.workflow_type",
        "evidence.has_obligation",
        "evidence.receipt_count",
        "observer.class",
        "observer.id",
        "observer.jurisdiction",
        "observer.region",
        "policy.is_violation",
    }
)
COLLECTION_FACT_FIELDS = frozenset(
    {
        "event.actor_ids",
        "evidence.types",
        "observer.relationship_types_to_event_actors",
    }
)
FACT_FIELDS = SCALAR_FACT_FIELDS | COLLECTION_FACT_FIELDS


class VisibilityLanguageError(ValueError):
    """Raised when a visibility expression or fact set is unsafe or ambiguous."""


def normalize_visibility_facts(values: Mapping[str, Any]) -> Mapping[str, Any]:
    unknown = sorted(set(values) - FACT_FIELDS)
    missing = sorted(FACT_FIELDS - set(values))
    if unknown or missing:
        raise VisibilityLanguageError(
            f"visibility facts must exactly cover the registry: missing={missing} unknown={unknown}"
        )
    normalized: dict[str, Any] = {}
    for field in sorted(SCALAR_FACT_FIELDS):
        value = values[field]
        if isinstance(value, (list, tuple, dict, set, frozenset)):
            raise VisibilityLanguageError(f"fact {field}: expected scalar or null")
        normalized[field] = value
    for field in sorted(COLLECTION_FACT_FIELDS):
        value = values[field]
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise VisibilityLanguageError(f"fact {field}: expected a scalar collection")
        if any(isinstance(item, (list, tuple, dict, set, frozenset)) for item in value):
            raise VisibilityLanguageError(f"fact {field}: nested values are forbidden")
        normalized[field] = tuple(sorted(set(value), key=lambda item: (type(item).__name__, str(item))))
    if not isinstance(normalized["event.id"], str) or not normalized["event.id"]:
        raise VisibilityLanguageError("event.id must be a non-empty string")
    if not isinstance(normalized["observer.id"], str) or not normalized["observer.id"]:
        raise VisibilityLanguageError("observer.id must be a non-empty string")
    if not isinstance(normalized["evidence.receipt_count"], int) or isinstance(
        normalized["evidence.receipt_count"], bool
    ):
        raise VisibilityLanguageError("evidence.receipt_count must be an integer")
    if normalized["evidence.receipt_count"] < 0:
        raise VisibilityLanguageError("evidence.receipt_count must be non-negative")
    for field in ("anomaly.workflow_member", "evidence.has_obligation", "policy.is_violation"):
        if not isinstance(normalized[field], bool):
            raise VisibilityLanguageError(f"fact {field}: expected bool")
    return MappingProxyType(normalized)


def validate_visibility_expression(expression: Mapping[str, Any]) -> None:
    node_count = [0]
    _validate_node(expression, depth=0, node_count=node_count)
    if node_count[0] > MAX_EXPRESSION_NODES:
        raise VisibilityLanguageError(
            f"visibility expression has {node_count[0]} nodes; maximum is {MAX_EXPRESSION_NODES}"
        )


def evaluate_visibility_expression(
    expression: Mapping[str, Any], facts: Mapping[str, Any]
) -> bool:
    validate_visibility_expression(expression)
    normalized = normalize_visibility_facts(facts)
    return _evaluate(expression, normalized)


def evaluate_validated_visibility_expression(
    expression: Mapping[str, Any], facts: Mapping[str, Any]
) -> bool:
    return _evaluate(expression, facts)


def _validate_node(expression: Any, *, depth: int, node_count: list[int]) -> None:
    if depth > MAX_EXPRESSION_DEPTH:
        raise VisibilityLanguageError(
            f"visibility expression depth exceeds {MAX_EXPRESSION_DEPTH}"
        )
    if not isinstance(expression, Mapping):
        raise VisibilityLanguageError("every visibility expression node must be an object")
    node_count[0] += 1
    operator = expression.get("op")
    if not isinstance(operator, str):
        raise VisibilityLanguageError("visibility expression requires string op")
    if operator == "const":
        _exact_keys(expression, {"op", "value"}, operator)
        if not isinstance(expression["value"], bool):
            raise VisibilityLanguageError("const.value must be bool")
        return
    if operator in {"all", "any"}:
        _exact_keys(expression, {"op", "args"}, operator)
        args = expression["args"]
        if not isinstance(args, list) or not args:
            raise VisibilityLanguageError(f"{operator}.args must be a non-empty list")
        for item in args:
            _validate_node(item, depth=depth + 1, node_count=node_count)
        return
    if operator == "not":
        _exact_keys(expression, {"op", "arg"}, operator)
        _validate_node(expression["arg"], depth=depth + 1, node_count=node_count)
        return
    if operator in {"eq", "ne"}:
        _exact_keys(expression, {"op", "field", "value"}, operator)
        _scalar_field(expression["field"])
        _scalar(expression["value"], f"{operator}.value")
        return
    if operator in {"in", "not_in", "intersects"}:
        _exact_keys(expression, {"op", "field", "values"}, operator)
        field = _field(expression["field"])
        values = expression["values"]
        if not isinstance(values, list) or not values:
            raise VisibilityLanguageError(f"{operator}.values must be a non-empty list")
        for value in values:
            _scalar(value, f"{operator}.values")
        if operator == "intersects" and field not in COLLECTION_FACT_FIELDS:
            raise VisibilityLanguageError("intersects requires a collection field")
        if operator in {"in", "not_in"} and field not in SCALAR_FACT_FIELDS:
            raise VisibilityLanguageError(f"{operator} requires a scalar field")
        return
    if operator == "contains_field":
        _exact_keys(expression, {"op", "field", "other_field"}, operator)
        field = _field(expression["field"])
        other = _field(expression["other_field"])
        if field not in COLLECTION_FACT_FIELDS or other not in SCALAR_FACT_FIELDS:
            raise VisibilityLanguageError(
                "contains_field requires collection field and scalar other_field"
            )
        return
    if operator == "eq_field":
        _exact_keys(expression, {"op", "field", "other_field"}, operator)
        _scalar_field(expression["field"])
        _scalar_field(expression["other_field"])
        return
    raise VisibilityLanguageError(f"unsupported visibility operator={operator!r}")


def _evaluate(expression: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    operator = expression["op"]
    if operator == "const":
        return bool(expression["value"])
    if operator == "all":
        return all(_evaluate(item, facts) for item in expression["args"])
    if operator == "any":
        return any(_evaluate(item, facts) for item in expression["args"])
    if operator == "not":
        return not _evaluate(expression["arg"], facts)
    if operator == "eq":
        return facts[expression["field"]] == expression["value"]
    if operator == "ne":
        return facts[expression["field"]] != expression["value"]
    if operator == "in":
        return facts[expression["field"]] in expression["values"]
    if operator == "not_in":
        return facts[expression["field"]] not in expression["values"]
    if operator == "intersects":
        return bool(set(facts[expression["field"]]) & set(expression["values"]))
    if operator == "contains_field":
        return facts[expression["other_field"]] in facts[expression["field"]]
    if operator == "eq_field":
        return facts[expression["field"]] == facts[expression["other_field"]]
    raise VisibilityLanguageError(f"unsupported validated operator={operator!r}")


def _field(value: Any) -> str:
    if not isinstance(value, str) or value not in FACT_FIELDS:
        raise VisibilityLanguageError(f"unknown visibility fact field={value!r}")
    return value


def _scalar_field(value: Any) -> str:
    field = _field(value)
    if field not in SCALAR_FACT_FIELDS:
        raise VisibilityLanguageError(f"field {field!r} is not scalar")
    return field


def _scalar(value: Any, path: str) -> None:
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        raise VisibilityLanguageError(f"{path} must be scalar")


def _exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    if set(value) != expected:
        raise VisibilityLanguageError(
            f"{path}: keys must be exactly {sorted(expected)}; observed={sorted(value)}"
        )
