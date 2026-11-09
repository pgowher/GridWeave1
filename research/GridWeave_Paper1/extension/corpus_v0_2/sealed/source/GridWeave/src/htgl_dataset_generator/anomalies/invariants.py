"""Independent invariant evaluation for valid/invalid counterfactual traces."""

from __future__ import annotations

from datetime import datetime
import hashlib
from typing import Any, Callable, Mapping, Sequence

from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.workflows import workflow_definitions

from .models import CounterfactualTrace, InvariantOutcome
from .registry import InvariantRegistry


class InvariantEvaluationError(ValueError):
    """Raised when an invariant cannot be evaluated deterministically."""


class IndependentInvariantChecker:
    """Evaluate the complete registry without trusting anomaly generator labels."""

    def __init__(self, registry: InvariantRegistry, *, contract: ContractSpec | None = None) -> None:
        self.registry = registry
        self.contract = contract if contract is not None else load_contract()
        self._checks: Mapping[str, Callable[[CounterfactualTrace, CounterfactualTrace | None, str | None], tuple[str, str]]] = {
            "INV-SCHEMA-CONFORMANT": self._schema,
            "INV-PHYSICAL-CONTEXT-UNCHANGED": self._physical,
            "INV-WORKFLOW-TRANSITION-LEGAL": self._workflow_transition,
            "INV-WORKFLOW-EVENT-COUNT-RECONCILED": self._workflow_count,
            "INV-PURPOSE-PERMITTED": self._purpose,
            "INV-CROSS-REGION-PERMISSION": self._cross_region,
            "INV-POLICY-TRACE-COMPLETE": self._policy_trace,
            "INV-RETENTION-DUTY-SATISFIED": self._retention,
            "INV-CAUSAL-PARENT-REQUIRED": self._causal_parent,
            "INV-CAUSAL-ACYCLIC": self._causal_acyclic,
            "INV-ERASURE-REPLICA-CLOSURE": self._erasure_closure,
            "INV-RECEIPT-MATCHES-ACTION": self._receipt_action,
            "INV-EVIDENCE-CRYPTO-VALID": self._evidence_crypto,
            "INV-OBSERVER-REQUIRED-EVIDENCE-VISIBLE": self._observer_visibility,
            "INV-OBSERVER-WORLD-TRUTH-UNCHANGED": self._observer_world,
            "INV-RECORDED-TIME-CAUSAL-ORDER": self._recorded_time,
            "INV-WORLD-TIME-UNCHANGED": self._world_time,
            "INV-SAMPLING-PROBABILITY-VALID": self._sampling_probability,
            "INV-SAMPLING-ESTIMATOR-ELIGIBLE": self._sampling_eligibility,
            "INV-SAME-ACTORS": self._same_actors,
            "INV-SAME-OBJECT": self._same_object,
            "INV-SAME-TIME": self._same_time,
        }
        registered = {item.invariant_id for item in registry.invariants}
        if registered != set(self._checks):
            raise InvariantEvaluationError(
                "checker coverage must exactly match invariant registry: "
                f"missing={sorted(registered-set(self._checks))} extra={sorted(set(self._checks)-registered)}"
            )

    def evaluate(
        self,
        trace: CounterfactualTrace,
        *,
        reference: CounterfactualTrace | None = None,
        anomaly_type: str | None = None,
    ) -> tuple[InvariantOutcome, ...]:
        outcomes: list[InvariantOutcome] = []
        for definition in self.registry.invariants:
            status, details = self._checks[definition.invariant_id](trace, reference, anomaly_type)
            if status not in {"pass", "fail", "not_applicable"}:
                raise InvariantEvaluationError(
                    f"{definition.invariant_id}: checker returned invalid status={status!r}"
                )
            outcomes.append(InvariantOutcome(definition.invariant_id, definition.domain, status, details))
        return tuple(sorted(outcomes, key=lambda item: item.invariant_id))

    def _schema(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        try:
            validate_record(self.contract, "workflow_instance", trace.workflow_instance)
            for row in trace.events:
                validate_record(self.contract, "governance_event", row)
            for row in trace.edges:
                validate_record(self.contract, "event_edge", row)
            for row in trace.replicas:
                validate_record(self.contract, "data_object_replica", row)
            for row in trace.obligations:
                validate_record(self.contract, "evidence_obligation", row)
            for row in trace.receipts:
                validate_record(self.contract, "evidence_receipt", row)
            for row in trace.sampling_membership:
                validate_record(self.contract, "sample_membership", row)
        except Exception as exc:
            return "fail", f"locked schema validation failed: {exc}"
        event_ids = {str(row["event_id"]) for row in trace.events}
        if len(event_ids) != len(trace.events):
            return "fail", "duplicate event IDs"
        unresolved = [
            str(row["edge_id"])
            for row in trace.edges
            if str(row["source_event_id"]) not in event_ids or str(row["target_event_id"]) not in event_ids
        ]
        return ("pass", "all counterfactual rows and internal edge endpoints validate") if not unresolved else ("fail", f"unresolved internal edges {unresolved[:4]}")

    def _physical(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if reference is None:
            return "pass", "source physical context digest is present"
        same = trace.physical_context_digest == reference.physical_context_digest
        return ("pass", "physical context digest unchanged") if same else ("fail", "physical context digest changed")

    def _workflow_transition(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        workflow_type = str(trace.workflow_instance["workflow_type"])
        definition = workflow_definitions().get(workflow_type)
        if definition is None:
            return "fail", f"workflow definition missing for {workflow_type}"
        legal = {
            (item.event_type, item.state_before, item.state_after)
            for item in definition.transitions
        }
        ordered = sorted(trace.events, key=lambda row: (int(row["workflow_step_index"]), str(row["event_id"])))
        for index, row in enumerate(ordered):
            triple = (str(row["event_type"]), str(row["workflow_state_before"]), str(row["workflow_state_after"]))
            if triple not in legal:
                return "fail", f"illegal transition at step={row['workflow_step_index']} triple={triple}"
            if index and str(ordered[index - 1]["workflow_state_after"]) != str(row["workflow_state_before"]):
                return "fail", f"state chain discontinuity at step={row['workflow_step_index']}"
        return "pass", f"{len(ordered)} transitions are legal and state-chained"

    def _workflow_count(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        expected = int(trace.workflow_instance["event_count"])
        if expected != len(trace.events):
            return "fail", f"workflow event_count={expected} episode rows={len(trace.events)}"
        if reference is not None and len(trace.events) != len(reference.events):
            return "fail", "counterfactual changed workflow event count"
        return "pass", f"event count reconciles at {expected}"

    def _purpose(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        violating = [
            event_id
            for event_id, item in trace.policy_evaluations.items()
            if bool(item["is_violation"]) and str(item["violation_type"]) == "unauthorized_purpose"
        ]
        return ("pass", "no recomputed unauthorized-purpose policy decision") if not violating else ("fail", f"unauthorized purpose events={violating}")

    def _cross_region(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        breaches = [
            event_id
            for event_id, item in trace.policy_evaluations.items()
            if bool(item["is_cross_region"])
            and bool(item["is_violation"])
            and str(item["violation_type"]) == "cross_region_rule_breach"
        ]
        return ("pass", "no recomputed cross-region policy breach") if not breaches else ("fail", f"cross-region breach events={breaches}")

    def _policy_trace(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.policy_evaluations:
            return "not_applicable", "no policy events in episode"
        incomplete = [
            event_id
            for event_id, item in trace.policy_evaluations.items()
            if not item["applied_rule_ids"] or not item["conflict_resolution_trace"] or not str(item["explanation_code"]).strip()
        ]
        return ("pass", "all policy decisions retain rule and explanation provenance") if not incomplete else ("fail", f"incomplete policy traces={incomplete}")

    def _retention(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        scoped = [row for row in trace.replicas if row["deletion_due_at"] is not None]
        if not scoped:
            return "not_applicable", "no replica deletion deadline in episode"
        premature = [
            str(row["replica_id"])
            for row in scoped
            if row["deleted_at"] is not None and _timestamp(str(row["deleted_at"])) < _timestamp(str(row["deletion_due_at"]))
        ]
        return ("pass", "no deletion precedes its declared due time") if not premature else ("fail", f"premature replica deletions={premature}")

    def _causal_parent(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if len(trace.events) < 2:
            return "not_applicable", "single-event workflow"
        ordered = sorted(
            trace.events,
            key=lambda row: (int(row["workflow_step_index"]), str(row["event_id"])),
        )
        required_pairs = {
            (str(row["source_event_id"]), str(row["target_event_id"]))
            for row in trace.edges
            if str(row["edge_type"]) == "precedes"
            and "S07-WORKFLOW-PRECEDES" in str(row.get("rule_id") or "")
        }
        missing = [
            str(ordered[index]["event_id"])
            for index in range(1, len(ordered))
            if (
                str(ordered[index - 1]["event_id"]),
                str(ordered[index]["event_id"]),
            )
            not in required_pairs
        ]
        return (
            ("pass", "every non-root workflow step retains its normalized required parent edge")
            if not missing
            else ("fail", f"orphan non-root events missing required parent edges={missing}")
        )

    def _causal_acyclic(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        event_ids = {str(row["event_id"]) for row in trace.events}
        indegree = {event_id: 0 for event_id in event_ids}
        children: dict[str, list[str]] = {event_id: [] for event_id in event_ids}
        for row in trace.edges:
            source = str(row["source_event_id"])
            target = str(row["target_event_id"])
            children[source].append(target)
            indegree[target] += 1
        queue = sorted(event_id for event_id, value in indegree.items() if value == 0)
        visited = 0
        while queue:
            current = queue.pop(0)
            visited += 1
            for child in sorted(children[current]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
                    queue.sort()
        return ("pass", "counterfactual graph is acyclic") if visited == len(event_ids) else ("fail", "counterfactual graph contains a cycle")

    def _erasure_closure(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        obligations = [
            row
            for row in trace.obligations
            if row["obligation_type"] == "provenance" and row["coverage_scope"] == "replica_set"
        ]
        if not obligations:
            return "not_applicable", "no erasure propagation obligation in episode"
        receipts_by_obligation: dict[str, list[Mapping[str, Any]]] = {}
        for row in trace.receipts:
            receipts_by_obligation.setdefault(str(row["obligation_id"]), []).append(row)
        missing: list[str] = []
        for obligation in obligations:
            obligation_id = str(obligation["obligation_id"])
            replica_id = str(obligation["subject_object_id"])
            matches = [
                row
                for row in receipts_by_obligation.get(obligation_id, ())
                if str(row["receipt_id"]) in trace.independently_valid_receipt_ids
                and str(row["verification_status_truth"]) == "valid"
                and replica_id in {str(value) for value in row["covers_replica_ids"]}
            ]
            if not matches:
                missing.append(replica_id)
        return ("pass", "all replica propagation duties have valid coverage") if not missing else ("fail", f"missing propagated replicas={sorted(missing)}")

    def _receipt_action(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        deletion_obligations = {
            str(row["obligation_id"]): str(row["subject_object_id"])
            for row in trace.obligations
            if row["obligation_type"] == "replica_deletion" and row["coverage_scope"] == "replica_set"
        }
        receipt_replicas = {
            deletion_obligations[str(row["obligation_id"])]
            for row in trace.receipts
            if str(row["obligation_id"]) in deletion_obligations
            and str(row["receipt_id"]) in trace.independently_valid_receipt_ids
            and str(row["verification_status_truth"]) == "valid"
        }
        if not receipt_replicas:
            return "not_applicable", "no independently valid replica-deletion receipt in episode"
        mismatched = sorted(
            replica_id
            for replica_id in receipt_replicas
            if trace.replica_action_status.get(replica_id) != "completed"
        )
        return ("pass", "every valid deletion receipt corresponds to completed modeled action truth") if not mismatched else ("fail", f"false confirmations for replicas={mismatched}")

    def _evidence_crypto(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.receipts:
            return "not_applicable", "no receipt in episode"
        invalid = sorted(
            str(row["receipt_id"])
            for row in trace.receipts
            if str(row["receipt_id"]) not in trace.independently_valid_receipt_ids
        )
        return ("pass", "all retained receipts independently verify") if not invalid else ("fail", f"invalid retained receipts={invalid}")

    def _observer_visibility(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.observer_required_receipt_ids:
            return "not_applicable", "no observer evidence requirement in episode"
        missing = sorted(trace.observer_required_receipt_ids - trace.observer_visible_receipt_ids)
        return ("pass", "all required evidence is present in counterfactual observer delivery") if not missing else ("fail", f"observer omitted required receipts={missing}")

    def _observer_world(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if reference is None or not trace.observer_required_receipt_ids:
            return "not_applicable", "observer pair reference or requirement is absent"
        same = _non_observer_digest(trace) == _non_observer_digest(reference)
        return ("pass", "observer edit leaves frozen world/evidence truth unchanged") if same else ("fail", "observer edit changed non-observer truth")

    def _recorded_time(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.edges:
            return "not_applicable", "no causal edge in episode"
        events = {str(row["event_id"]): row for row in trace.events}
        conflicts: list[str] = []
        for edge in trace.edges:
            source = events[str(edge["source_event_id"])]
            target = events[str(edge["target_event_id"])]
            source_time = _timestamp(str(source["recorded_timestamp"] or source["timestamp"]))
            target_time = _timestamp(str(target["recorded_timestamp"] or target["timestamp"]))
            if target_time < source_time:
                conflicts.append(str(edge["edge_id"]))
        return ("pass", "recorded times respect all episode edges") if not conflicts else ("fail", f"recorded-time conflicts on edges={conflicts}")

    def _world_time(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if reference is None:
            return "pass", "source world timestamps are explicit"
        same = _event_projection(trace.events, ("event_id", "timestamp")) == _event_projection(reference.events, ("event_id", "timestamp"))
        return ("pass", "canonical world timestamps unchanged") if same else ("fail", "canonical world timestamp changed")

    def _sampling_probability(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.sampling_membership:
            return "not_applicable", "sampling stage has not materialized membership for this trace"
        invalid = [
            str(row["unit_id"])
            for row in trace.sampling_membership
            if not 0.0 < float(row["first_order_inclusion_probability"]) <= 1.0
            or abs(float(row["design_weight"]) - 1.0 / float(row["first_order_inclusion_probability"])) > 1e-9
        ]
        return ("pass", "sampling probabilities and inverse weights validate") if not invalid else ("fail", f"invalid sampling units={invalid}")

    def _sampling_eligibility(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if not trace.sampling_membership:
            return "not_applicable", "sampling estimator eligibility is not asserted"
        ineligible = [str(row["unit_id"]) for row in trace.sampling_membership if not bool(row["estimator_eligible"])]
        return ("pass", "all sampled units explicitly declare estimator eligibility") if not ineligible else ("fail", f"ineligible sampling units={ineligible}")

    def _same_actors(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if reference is None:
            return "pass", "source actor fields are explicit"
        fields = ("event_id", "source_actor_id", "requesting_actor_id", "controller_actor_id", "processor_actor_id", "oversight_actor_id")
        left = _event_projection(reference.events, fields)
        right = _event_projection(trace.events, fields)
        if left == right:
            return "pass", "actor fields unchanged"
        if anomaly_type == "cross_region_rule_breach":
            permitted_fields = {"requesting_actor_id"}
            changes = _changed_event_fields(reference.events, trace.events, fields[1:])
            if changes and {field for _, field in changes} <= permitted_fields and len(changes) == 1:
                return "pass", "only grammar-permitted destination actor substitution occurred"
        return "fail", "actor fields changed outside target grammar"

    def _same_object(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        if reference is None:
            return "pass", "source object fields are explicit"
        fields = ("event_id", "data_object_id", "local_database_id")
        same = _event_projection(reference.events, fields) == _event_projection(trace.events, fields)
        return ("pass", "object and database identities unchanged") if same else ("fail", "object or database identity changed")

    def _same_time(self, trace: CounterfactualTrace, reference: CounterfactualTrace | None, anomaly_type: str | None) -> tuple[str, str]:
        return self._world_time(trace, reference, anomaly_type)


def outcome_by_id(outcomes: Sequence[InvariantOutcome]) -> Mapping[str, InvariantOutcome]:
    result = {item.invariant_id: item for item in outcomes}
    if len(result) != len(outcomes):
        raise InvariantEvaluationError("duplicate invariant outcomes")
    return result


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvariantEvaluationError(f"timestamp is not timezone-aware: {value!r}")
    return parsed


def _event_projection(events: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> tuple[tuple[Any, ...], ...]:
    return tuple(sorted(tuple(row[field] for field in fields) for row in events))


def _changed_event_fields(
    valid_events: Sequence[Mapping[str, Any]],
    invalid_events: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> tuple[tuple[str, str], ...]:
    valid = {str(row["event_id"]): row for row in valid_events}
    invalid = {str(row["event_id"]): row for row in invalid_events}
    changes: list[tuple[str, str]] = []
    for event_id in sorted(set(valid) & set(invalid)):
        for field in fields:
            if valid[event_id][field] != invalid[event_id][field]:
                changes.append((event_id, field))
    return tuple(changes)


def _non_observer_digest(trace: CounterfactualTrace) -> str:
    payload = dict(trace.as_payload())
    payload.pop("observer_required_receipt_ids", None)
    payload.pop("observer_visible_receipt_ids", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
