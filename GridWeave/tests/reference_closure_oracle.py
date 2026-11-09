"""Independent executable oracle for the Phase 2.2 worked-case suite.

This module intentionally imports no ``htgl_dataset_generator`` code.  It is a
small executable reading of the normative predicates, suitable for checking a
manual evaluation record without sharing PaEGen or VERCLO implementation logic.
"""

from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping


TERMINAL_OUTCOMES = (
    "CLOSED",
    "CLOSED_WITH_EXCEPTIONS",
    "PARTIALLY_CLOSED",
    "OPEN",
    "DISPUTED",
    "UNVERIFIABLE",
)
SUCCESS_DISPOSITIONS = {"ERASED", "CRYPTO_ERASED", "APPROVED_TRANSFORM"}


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _acyclic(vertices: set[str], edges: list[Mapping[str, Any]]) -> bool:
    indegree = {vertex: 0 for vertex in vertices}
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        source = edge["source_asset_id"]
        target = edge["target_asset_id"]
        if target not in adjacency[source]:
            adjacency[source].add(target)
            indegree[target] += 1
    queue = deque(sorted(vertex for vertex, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        source = queue.popleft()
        visited += 1
        for target in sorted(adjacency[source]):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited == len(vertices)


def materialize_case(suite: Mapping[str, Any], case: Mapping[str, Any]) -> dict[str, Any]:
    forbidden = {"expected_outcome", "oracle", "manual"} & set(case)
    if forbidden:
        raise ValueError(f"oracle input contains forbidden answer fields: {sorted(forbidden)}")
    return _merge(suite["defaults"], case)


def evaluate_case(suite: Mapping[str, Any], raw_case: Mapping[str, Any]) -> dict[str, Any]:
    case = materialize_case(suite, raw_case)
    at = _time(case["evaluation_time"])
    case_deadline = _time(case["case_deadline"])
    policy = case["policy"]
    assets = {row["asset_id"]: row for row in case["assets"]}

    visible_edges = []
    dangling_visible_edge = False
    for edge in case["lineage"]:
        status = edge["status"]
        visible = status == "DECLARED" or (
            status == "DISCOVERABLE"
            and edge.get("authenticated", False)
            and edge.get("disclosed_at") is not None
            and _time(edge["disclosed_at"]) <= at
        )
        if not visible:
            continue
        if edge["source_asset_id"] not in assets or edge["target_asset_id"] not in assets:
            dangling_visible_edge = True
        else:
            visible_edges.append(edge)

    reached = set(case["root_asset_ids"])
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in visible_edges:
        if edge.get("authenticated", False):
            adjacency[edge["source_asset_id"]].add(edge["target_asset_id"])
    queue = deque(sorted(reached))
    while queue:
        source = queue.popleft()
        for target in sorted(adjacency[source]):
            if target not in reached:
                reached.add(target)
                queue.append(target)

    roots_resolve = all(root in assets for root in case["root_asset_ids"])
    visible_replicas = [
        row
        for row in case["replicas"]
        if row.get("status", "DECLARED") == "DECLARED"
        or (
            row.get("status") == "DISCOVERABLE"
            and row.get("authenticated", False)
            and row.get("disclosed_at") is not None
            and _time(row["disclosed_at"]) <= at
        )
    ]
    replicas_resolve = all(row["asset_id"] in assets for row in visible_replicas)
    identifiers_unique = (
        len(assets) == len(case["assets"])
        and len({row["replica_id"] for row in visible_replicas}) == len(visible_replicas)
    )
    visible_material_authenticated = all(
        edge["authenticated"] for edge in visible_edges
    ) and all(replica["authenticated"] for replica in visible_replicas)
    declared_scope_complete = (
        case["baseline"]["scope_commitment_valid"]
        and case["baseline"]["graph_available"]
        and roots_resolve
        and replicas_resolve
        and not dangling_visible_edge
        and identifiers_unique
        and visible_material_authenticated
        and _acyclic(set(assets), visible_edges)
    )

    obligations: list[dict[str, Any]] = []
    for replica in visible_replicas:
        asset = assets.get(replica["asset_id"])
        if asset is None or asset["asset_id"] not in reached:
            continue
        if asset["kind"] not in policy["applicable_asset_kinds"]:
            continue
        if replica["replica_class"] not in policy["applicable_replica_classes"]:
            continue
        obligations.append(
            {
                "obligation_id": f"OBL::{asset['asset_id']}::{replica['replica_id']}",
                "asset_id": asset["asset_id"],
                "replica_id": replica["replica_id"],
                "repository_id": replica["repository_id"],
                "custodian_id": replica["custodian_id"],
                "deadline": replica.get("deadline", case["case_deadline"]),
                "minimum_grade": replica.get("minimum_grade", policy["minimum_grade"]),
                "allowed_dispositions": replica.get(
                    "allowed_dispositions", policy["allowed_dispositions"]
                ),
            }
        )
    obligations.sort(key=lambda row: row["obligation_id"])
    obligation_by_id = {row["obligation_id"]: row for row in obligations}

    committed = case["baseline"].get("committed_obligation_ids", "AUTO")
    induced_ids = sorted(obligation_by_id)
    commitment_matches = committed == "AUTO" or sorted(committed) == induced_ids
    obligation_set_complete = (
        case["baseline"]["obligation_commitment_valid"] and commitment_matches
    )

    no_applicable_valid = bool(case["baseline"].get("no_applicable_determination_valid"))
    authorization_valid = bool(case["baseline"]["authorization_valid"])
    baseline_verifiable = all(
        (
            authorization_valid,
            case["baseline"]["policy_authenticated"],
            declared_scope_complete,
            obligation_set_complete,
            bool(obligations) or no_applicable_valid,
        )
    )

    admissible_assertions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    valid_success: set[str] = set()
    evidence_checks: list[bool] = []
    continuity_checks: list[bool] = []
    for evidence in case["evidence"]:
        obligation = obligation_by_id.get(evidence["obligation_id"])
        if obligation is None:
            evidence_checks.append(False)
            continuity_checks.append(False)
            continue
        continuity = all(
            (
                evidence["continuity"]["chain_authenticated"],
                evidence["continuity"]["sequence_contiguous"],
                evidence["continuity"]["predecessors_available"],
            )
        )
        continuity_checks.append(continuity)
        base_valid = all(
            (
                evidence["authenticated"],
                evidence["binding_valid"],
                evidence["integrity_valid"],
                evidence["ordering_valid"],
                evidence["issuer_id"] == obligation["custodian_id"],
                evidence["grade"] >= obligation["minimum_grade"],
                _time(evidence["event_time"]) <= at,
                continuity,
            )
        )
        evidence_checks.append(base_valid)
        if not base_valid:
            continue
        admissible_assertions[obligation["obligation_id"]].append(evidence)
        if (
            evidence["disposition"] in SUCCESS_DISPOSITIONS
            and evidence["disposition"] in obligation["allowed_dispositions"]
            and _time(evidence["event_time"]) <= _time(obligation["deadline"])
        ):
            valid_success.add(obligation["obligation_id"])

    valid_exception: set[str] = set()
    exception_checks: list[bool] = []
    authorities = set(policy["exception_authority_ids"])
    for exception in case["exceptions"]:
        covered_checks: list[bool] = []
        for obligation_id in exception["obligation_ids"]:
            obligation = obligation_by_id.get(obligation_id)
            if obligation is None:
                covered_checks.append(False)
                continue
            valid = all(
                (
                    exception["authenticated"],
                    exception["authority_id"] in authorities,
                    bool(exception["basis_commitment"]),
                    _time(exception["effective_at"]) <= _time(obligation["deadline"]),
                    at < _time(exception["expires_at"]),
                )
            )
            covered_checks.append(valid)
            if valid:
                valid_exception.add(obligation_id)
        exception_checks.append(bool(covered_checks) and all(covered_checks))

    conflict_ids = sorted(
        obligation_id
        for obligation_id, rows in admissible_assertions.items()
        if len({row["disposition"] for row in rows}) > 1
    )
    active_challenge = any(
        row["authenticated"] and not row["resolved"] for row in case["challenges"]
    )
    contradiction_free = not conflict_ids and not active_challenge
    resolved = valid_success | valid_exception
    obligation_coverage = set(obligation_by_id) <= resolved
    evidence_validity = all(evidence_checks)
    exception_justification = all(exception_checks)
    evidence_continuity = all(continuity_checks)

    has_terminal_report = {
        obligation_id
        for obligation_id in obligation_by_id
        if admissible_assertions.get(obligation_id) or obligation_id in valid_exception
    }
    ready = at >= case_deadline or (
        policy["early_closure_allowed"]
        and set(obligation_by_id) <= has_terminal_report
        and (bool(obligations) or no_applicable_valid)
    )

    if not ready:
        outcome = "IN_PROGRESS"
    elif not baseline_verifiable:
        outcome = "UNVERIFIABLE"
    elif not contradiction_free:
        outcome = "DISPUTED"
    elif set(obligation_by_id) <= valid_success:
        outcome = "CLOSED"
    elif obligation_coverage and valid_exception:
        outcome = "CLOSED_WITH_EXCEPTIONS"
    elif resolved:
        outcome = "PARTIALLY_CLOSED"
    else:
        outcome = "OPEN"

    return {
        "case_id": case["case_id"],
        "outcome": outcome,
        "discovered_asset_ids": sorted(reached),
        "obligation_ids": induced_ids,
        "resolved_obligation_ids": sorted(resolved),
        "conflict_obligation_ids": conflict_ids,
        "predicates": {
            "authorization_valid": authorization_valid,
            "declared_scope_complete": declared_scope_complete,
            "obligation_set_complete": obligation_set_complete,
            "obligation_coverage": obligation_coverage,
            "evidence_validity": evidence_validity,
            "contradiction_free": contradiction_free,
            "exception_justification": exception_justification,
            "evidence_continuity": evidence_continuity,
            "baseline_verifiable": baseline_verifiable,
            "ready": ready,
        },
    }
