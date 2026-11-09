"""Manual model-to-code boundary fixtures for the current research evaluator."""

from __future__ import annotations

import argparse
import os
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'HTGLThesis/src'))

from abstract_model import Observation, decide, positive_soundness_holds  # noqa: E402
from analytics.closure_report import ClosureClass  # noqa: E402
from disputes.models import ChallengeKind, DisputeClosureState  # noqa: E402
from disputes.service import ChallengeDisputeService  # noqa: E402
from erasure.federated_closure_evaluator import FederatedClosureEvaluator  # noqa: E402
from evidence.models import BackendValidation, CustodianReceipt, ExceptionValidation  # noqa: E402
from evidence.receipt_verifier import CustodianReceiptVerifier  # noqa: E402
from proof.evidence_grade_evaluator import EvidenceGradeEvaluator  # noqa: E402
from proof.network_backends import (  # noqa: E402
    NetworkMerkleValidationBackend, NetworkPBFTCluster,
    NetworkSignedValidationBackend, deterministic_private_key, serve_merkle_authority,
    serve_signed_authority,
)
from proof.validation_backend import DeterministicValidationBackend  # noqa: E402
from verclo.graph_builder import ObligationGraphBuilder  # noqa: E402
from verclo.models import (  # noqa: E402
    AssetDescriptor, CasePhase, ErasureCase, ExceptionAssertion, LineageEdge,
    Obligation, ObligationGraph, ReplicaDescriptor, RepositoryDescriptor,
    TopologyView,
)
from verclo.policy import PolicyRegistry  # noqa: E402


UTC = timezone.utc
ACCEPTED = datetime(2026, 8, 1, tzinfo=UTC)
DEADLINE = ACCEPTED + timedelta(days=30)
AFTER = DEADLINE + timedelta(days=1)
BEFORE = ACCEPTED + timedelta(days=1)
PROFILE = "VERCLO-POLICY-TECHNICAL-ERASURE"
POLICIES = PolicyRegistry.load()


@dataclass(frozen=True)
class Scenario:
    name: str
    categories: tuple[str, ...]
    expected: str
    receipts: tuple[tuple[int, str, str, str], ...] = ()
    baseline: bool = True
    before_deadline: bool = False
    exception_index: int | None = None
    exception_mode: str = "none"
    challenge: bool = False
    dispute_outcome: str | None = None
    bad_authenticator: bool = False
    graph_missing: bool = False
    ready_override: bool | None = None
    accepted_difference: str | None = None


SCENARIOS = (
    Scenario("closed", ("COVERED",), "CLOSED", ((1, "R-1", "ERASED", "on_time"),)),
    Scenario("closed_with_exception", ("COVERED", "EXCEPTED"), "CLOSED_WITH_EXCEPTIONS",
             ((1, "R-1", "ERASED", "on_time"),), exception_index=2, exception_mode="valid"),
    Scenario("partial", ("COVERED", "MISSING"), "PARTIALLY_CLOSED",
             ((1, "R-1", "ERASED", "on_time"),)),
    Scenario("open", ("MISSING",), "OPEN"),
    Scenario("disputed_conflict", ("CONTRADICTORY",), "DISPUTED",
             ((1, "R-1", "ERASED", "on_time"), (1, "R-2", "FAILED", "on_time"))),
    Scenario("unverifiable_baseline", (), "UNVERIFIABLE", baseline=False),
    Scenario("in_progress", ("MISSING",), "IN_PROGRESS", before_deadline=True),
    Scenario("late_evidence", ("LATE",), "OPEN", ((1, "R-LATE", "ERASED", "late"),)),
    Scenario("invalid_evidence", ("INVALID",), "OPEN", ((1, "R-BAD", "ERASED", "on_time"),),
             bad_authenticator=True),
    Scenario("active_challenge", ("COVERED",), "DISPUTED",
             ((1, "R-1", "ERASED", "on_time"),), challenge=True),
    Scenario("challenge_timeout_baseline", (), "UNVERIFIABLE", dispute_outcome="UNVERIFIABLE"),
    Scenario("exception_expired", ("MISSING",), "OPEN", exception_index=1,
             exception_mode="expired"),
    Scenario("trust_context_rotated", ("INVALID",), "OPEN",
             ((1, "R-1", "ERASED", "on_time"),), bad_authenticator=True),
    Scenario("graph_unavailable", (), "UNVERIFIABLE", graph_missing=True),
    Scenario("empty_unattested_obligations", (), "UNVERIFIABLE",
             accepted_difference="v1.4 closes an empty graph without a NO_APPLICABLE_OBLIGATIONS attestation"),
    Scenario("challenge_before_deadline", ("MISSING",), "IN_PROGRESS",
             before_deadline=True, challenge=True,
             accepted_difference="v1.4 gives an open challenge precedence over readiness"),
    # Expected counterexamples are retained rather than redefining the old model.
    Scenario("invalid_baseline_before_deadline", (), "IN_PROGRESS", baseline=False,
             before_deadline=True, accepted_difference="v1.4 evaluates baseline before readiness"),
    Scenario("exception_at_expiry", ("MISSING",), "OPEN", exception_index=1,
             exception_mode="boundary", accepted_difference="v1.4 accepts exception at expires_at"),
)


def _obligation(case_id: str, number: int) -> Obligation:
    return Obligation(
        obligation_id=f"OBL-{number}", case_id=case_id, dataset_id="DATASET-0",
        correlation_id="CORR-0", asset_id=f"ASSET-{number}",
        replica_id=f"REPLICA-{number}", repository_id=f"REPO-{number}",
        custodian_principal_id=f"CUSTODIAN-{number}", deadline=DEADLINE,
        minimum_evidence_grade="E2", permitted_dispositions=("ERASED", "CRYPTO_ERASED"),
        policy_profile_id=PROFILE, policy_version="1.0.0",
    )


def _case(spec: Scenario) -> tuple[ErasureCase, tuple[CustodianReceipt, ...],
                                   tuple[ExceptionValidation, ...],
                                   DisputeClosureState | None]:
    case_id = f"E0-{spec.name}"
    count = len(spec.categories)
    obligations = tuple(_obligation(case_id, index) for index in range(1, count + 1))
    eval_time = BEFORE if spec.before_deadline else AFTER
    exceptions: tuple[ExceptionAssertion, ...] = ()
    checks: tuple[ExceptionValidation, ...] = ()
    if spec.exception_index is not None:
        expiry = eval_time if spec.exception_mode == "boundary" else (
            eval_time - timedelta(seconds=1) if spec.exception_mode == "expired"
            else eval_time + timedelta(days=1)
        )
        exceptions = (ExceptionAssertion(
            exception_id="EX-1", obligation_id=f"OBL-{spec.exception_index}",
            authority_principal_id="AUTHORITY-RETENTION-REVIEW", basis_commitment="a" * 64,
            effective_at=ACCEPTED, expires_at=expiry,
        ),)
        checks = (ExceptionValidation("EX-1", True, True),)
    graph = None if spec.graph_missing else ObligationGraph(
        case_id=case_id, dataset_id="DATASET-0", correlation_id="CORR-0", scope_version=1,
        root_asset_ids=("ASSET-1",), discovered_asset_ids=tuple(row.asset_id for row in obligations),
        relationship_ids=(), obligations=obligations, exceptions=exceptions,
        custodians=tuple(row.custodian_principal_id for row in obligations),
        scope_commitment="a" * 64, obligation_commitment="b" * 64,
        baseline_verifiable=spec.baseline,
        baseline_reason_codes=() if spec.baseline else ("OBLIGATION_COMMITMENT_MISMATCH",),
    )
    case = ErasureCase(
        case_id=case_id, run_id="RUN-0", dataset_id="DATASET-0", correlation_id="CORR-0",
        request_id="REQ-0", requester_principal_id="REQUESTER-0",
        root_asset_ids=("ASSET-1",), policy_profile_id=PROFILE, accepted_at=ACCEPTED,
        phase=CasePhase.OBLIGATIONS_ACTIVE, revision=1, graph=graph,
    )
    receipts = tuple(CustodianReceipt(
        receipt_id=receipt_id, case_id=case_id, obligation_id=f"OBL-{index}",
        asset_id=f"ASSET-{index}", replica_id=f"REPLICA-{index}",
        repository_id=f"REPO-{index}", issuer_principal_id=f"CUSTODIAN-{index}",
        issuer_role="CUSTODIAN", trust_domain="TRUST-0", fault_domain="FAULT-0",
        evidence_type="signature", disposition=disposition,
        event_time=DEADLINE + timedelta(seconds=1) if timing == "late" else ACCEPTED,
        submitted_at=DEADLINE + timedelta(seconds=1) if timing == "late" else ACCEPTED,
        not_before=ACCEPTED, provenance_refs=("PROV-0",),
    ) for index, receipt_id, disposition, timing in spec.receipts)
    dispute = None
    if spec.challenge or spec.dispute_outcome:
        service = ChallengeDisputeService.from_config()
        opened_at = ACCEPTED if spec.dispute_outcome else eval_time
        service.issue_challenge(
            case_id=case_id, challenge_id="CH-1", kind=ChallengeKind.SCOPE,
            target_ref=case_id, challenger_principal_id="CHALLENGER-0",
            grounds_commitment="c" * 64, opened_at=opened_at,
            known_target_refs=(case_id,),
        )
        dispute = service.closure_state(case_id, eval_time)
        if not service.verify_journal(case_id):
            raise AssertionError("dispute journal failed verification")
    return case, receipts, checks, dispute


def _backend(spec: Scenario):
    values = {receipt_id: BackendValidation(
        "fixture", anchor_valid=True, ordering_support_valid=True,
        authenticator_valid=not spec.bad_authenticator,
    ) for _, receipt_id, _, _ in spec.receipts}
    return DeterministicValidationBackend(values)


def _evaluator(backend) -> FederatedClosureEvaluator:
    return FederatedClosureEvaluator(
        EvidenceGradeEvaluator(CustodianReceiptVerifier(backend)), POLICIES
    )


def _raw_report(report) -> dict[str, Any]:
    """Serialize every full-report field, including backend transport fields."""
    value = asdict(report)
    def convert(item):
        if isinstance(item, dict):
            return {key: convert(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [convert(child) for child in item]
        if isinstance(item, datetime):
            return item.isoformat()
        return item
    return convert(value)


def _semantic_report(report) -> dict[str, Any]:
    """All report fields except transport identity and backend-only diagnostics."""
    def strip_transport(item):
        if isinstance(item, dict):
            return {key: strip_transport(child) for key, child in item.items()
                    if key not in {"backend_name", "diagnostics"}}
        if isinstance(item, list):
            return [strip_transport(child) for child in item]
        return item
    return strip_transport(_raw_report(report))


def run_cases() -> dict[str, Any]:
    rows = []
    for spec in SCENARIOS:
        case, receipts, exception_checks, dispute = _case(spec)
        evaluation_time = BEFORE if spec.before_deadline else AFTER
        report = _evaluator(_backend(spec)).evaluate(
            case, receipts, evaluation_time, exception_validations=exception_checks,
            dispute_state=dispute,
        )
        abstract = Observation(
            baseline_verifiable=spec.baseline and not spec.graph_missing
                and spec.dispute_outcome != "UNVERIFIABLE" and bool(spec.categories),
            ready=(not spec.before_deadline if spec.ready_override is None else spec.ready_override),
            conflict_or_challenge=spec.challenge or spec.dispute_outcome == "DISPUTED",
            categories=spec.categories,
        )
        model_outcome = decide(abstract)
        observed_categories = tuple(str(row.category) for row in report.obligation_results)
        observed = str(report.closure_class)
        match = model_outcome == observed and (
            model_outcome == "UNVERIFIABLE" or observed_categories == spec.categories
        )
        positive_sound = observed not in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"} or (
            case.graph is not None and case.graph.baseline_verifiable
            and abstract.baseline_verifiable and model_outcome in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}
            and all(row.category in {"COVERED", "EXCEPTED"} for row in report.obligation_results)
            and not spec.challenge and dispute is None
            and not any(row.category == "CONTRADICTORY" for row in report.obligation_results)
        )
        semantic = _semantic_report(report)
        expected_full = None
        rows.append({
            "scenario": spec.name, "model_outcome": model_outcome,
            "implementation_outcome": observed, "expected_categories": spec.categories,
            "observed_categories": observed_categories, "model_alignment": match,
            "known_difference": spec.accepted_difference,
            "positive_soundness": bool(positive_sound and positive_soundness_holds(abstract)),
            "expected_full_report_present": expected_full is not None,
            "full_report_fixture_equal": expected_full == semantic if expected_full is not None else None,
            "report": semantic,
        })
    return {
        "cases": rows,
        "unexpected_mismatches": [row["scenario"] for row in rows
                                  if not row["model_alignment"] and not row["known_difference"]],
        "known_mismatches": [row["scenario"] for row in rows
                             if not row["model_alignment"] and row["known_difference"]],
        "full_report_fixture_mismatches": [row["scenario"] for row in rows
                                           if row["full_report_fixture_equal"] is False],
        "full_report_fixtures_missing": [row["scenario"] for row in rows
                                         if not row["expected_full_report_present"]],
    }


def run_disclosure_pair() -> dict[str, Any]:
    """Exercise graph_builder on authenticated addition, then re-evaluate closure."""
    builder = ObligationGraphBuilder()
    policy = POLICIES.get(PROFILE)
    base = dict(case_id="E0-disclosure", dataset_id="DATASET-0",
                correlation_id="CORR-0")
    assets = (AssetDescriptor("A-ROOT", "DATASET-0", "interval_reading"),
              AssetDescriptor("A-DERIVED", "DATASET-0", "feature"))
    repositories = (RepositoryDescriptor("REPO-ROOT", "ORG-0", "CUSTODIAN-0", "primary"),
                    RepositoryDescriptor("REPO-DERIVED", "ORG-1", "CUSTODIAN-1", "derived"))
    replicas = (ReplicaDescriptor("REP-ROOT", "A-ROOT", "REPO-ROOT", "primary"),
                ReplicaDescriptor("REP-DERIVED", "A-DERIVED", "REPO-DERIVED", "derived"))
    initial = TopologyView(**base, scope_version=1, assets=assets, repositories=repositories,
                           replicas=replicas, lineage_edges=(), scope_commitment=None)
    later = replace(initial, scope_version=2, lineage_edges=(LineageEdge(
        "EDGE-1", "A-ROOT", "A-DERIVED", "DERIVED_FROM"),))
    initial = replace(initial, scope_commitment=builder.expected_scope_commitment(initial))
    later = replace(later, scope_commitment=builder.expected_scope_commitment(later))
    first_graph = builder.build(view=initial, root_asset_ids=("A-ROOT",),
                                accepted_at=ACCEPTED, policy=policy)
    later_graph = builder.build(view=later, root_asset_ids=("A-ROOT",),
                                accepted_at=ACCEPTED, policy=policy)
    def case(graph, revision):
        return ErasureCase("E0-disclosure", "RUN-0", "DATASET-0", "CORR-0", "REQ-0",
                           "REQUESTER-0", ("A-ROOT",), PROFILE, ACCEPTED,
                           CasePhase.OBLIGATIONS_ACTIVE, revision, graph)
    root = first_graph.obligations[0]
    receipt = CustodianReceipt(
        receipt_id="R-ROOT", case_id=root.case_id, obligation_id=root.obligation_id,
        asset_id=root.asset_id, replica_id=root.replica_id,
        repository_id=root.repository_id, issuer_principal_id=root.custodian_principal_id,
        issuer_role="CUSTODIAN", trust_domain="TRUST-0", fault_domain="FAULT-0",
        evidence_type="signature", disposition="ERASED", event_time=ACCEPTED,
        submitted_at=ACCEPTED, not_before=ACCEPTED, provenance_refs=("PROV-0",),
    )
    backend = DeterministicValidationBackend({"R-ROOT": BackendValidation(
        "fixture", anchor_valid=True, ordering_support_valid=True)})
    evaluator = _evaluator(backend)
    first = evaluator.evaluate(case(first_graph, 1), (receipt,), AFTER)
    second = evaluator.evaluate(case(later_graph, 2), (receipt,), AFTER)
    return {
        "initial_obligations": len(first_graph.obligations),
        "disclosed_obligations": len(later_graph.obligations),
        "initial_outcome": str(first.closure_class),
        "after_disclosure_outcome": str(second.closure_class),
        "passed": first_graph.baseline_verifiable and later_graph.baseline_verifiable
            and len(first_graph.obligations) == 1 and len(later_graph.obligations) == 2
            and first.closure_class == ClosureClass.CLOSED
            and second.closure_class == ClosureClass.PARTIALLY_CLOSED,
        "initial_report": _semantic_report(first),
        "after_disclosure_report": _semantic_report(second),
    }


