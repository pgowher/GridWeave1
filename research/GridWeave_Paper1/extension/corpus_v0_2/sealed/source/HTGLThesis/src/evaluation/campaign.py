"""Reference VERCLO fault campaign and comparative decision metrics."""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evidence.models import (
    BackendValidation,
    CustodianReceipt,
    ExceptionValidation,
    ReceiptValidationBackend,
)
from jsonschema import Draft202012Validator
from proof.validation_backend import (
    DeterministicValidationBackend,
    PBFTValidationBackend,
)
from verclo.models import (
    CasePhase,
    ErasureCase,
    ExceptionAssertion,
    Obligation,
    ObligationGraph,
)

from .distributed_faults import PBFTFaultProfile, SimulatedPBFTClient
from .fault_injection import FaultInjector, FaultKind, FaultSpec
from .policy_comparison import ComparisonPolicy, PolicyComparator

UTC = timezone.utc
ACCEPTED_AT = datetime(2026, 8, 1, tzinfo=UTC)
DEADLINE = datetime(2026, 9, 1, tzinfo=UTC)
EVALUATION_TIME = datetime(2026, 9, 2, tzinfo=UTC)
DEFAULT_CONFIG = (
    Path(__file__).resolve().parent / "configs" / "verclo_publication_campaign_v1.json"
)
CONFIG_SCHEMA = DEFAULT_CONFIG.with_name("verclo_publication_campaign_v1.schema.json")
REPORT_SCHEMA = DEFAULT_CONFIG.with_name("verclo_publication_report_v1.schema.json")


@dataclass(frozen=True)
class EvaluationScenario:
    scenario_id: str
    fault_family: str
    expected_closed: bool
    case: ErasureCase
    receipts: tuple[CustodianReceipt, ...]
    backend: ReceiptValidationBackend
    exception_validations: tuple[ExceptionValidation, ...] = ()
    open_challenge_ids: tuple[str, ...] = ()
    injected_faults: tuple[str, ...] = ()
    mutation_log: tuple[str, ...] = ()


@dataclass(frozen=True)
class CampaignReport:
    payload: Mapping[str, object]

    @property
    def report_sha256(self) -> str:
        return str(self.payload["report_sha256"])

    def to_dict(self) -> dict[str, object]:
        return dict(self.payload)


def _obligation(case_id: str, number: int, grade: str = "E2") -> Obligation:
    return Obligation(
        obligation_id=f"{case_id}:OBL:{number}",
        case_id=case_id,
        dataset_id="DATASET-PUBLICATION",
        correlation_id=f"CORR:{case_id}",
        asset_id=f"{case_id}:ASSET:{number}",
        replica_id=f"{case_id}:REPLICA:{number}",
        repository_id=f"{case_id}:REPOSITORY:{number}",
        custodian_principal_id=f"{case_id}:CUSTODIAN:{number}",
        deadline=DEADLINE,
        minimum_evidence_grade=grade,
        permitted_dispositions=("CRYPTO_ERASED", "ERASED"),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE",
        policy_version="1.0.0",
    )


def _case(
    case_id: str,
    *,
    count: int = 1,
    grade: str = "E2",
    exception: bool = False,
) -> ErasureCase:
    obligations = tuple(
        _obligation(case_id, index, grade) for index in range(1, count + 1)
    )
    exceptions: tuple[ExceptionAssertion, ...] = ()
    if exception:
        exceptions = (
            ExceptionAssertion(
                exception_id=f"{case_id}:EXCEPTION:1",
                obligation_id=obligations[0].obligation_id,
                authority_principal_id="AUTHORITY-RETENTION-REVIEW",
                basis_commitment="a" * 64,
                effective_at=ACCEPTED_AT,
                expires_at=EVALUATION_TIME + timedelta(days=1),
            ),
        )
    graph = ObligationGraph(
        case_id=case_id,
        dataset_id="DATASET-PUBLICATION",
        correlation_id=f"CORR:{case_id}",
        scope_version=1,
        root_asset_ids=(obligations[0].asset_id,),
        discovered_asset_ids=tuple(row.asset_id for row in obligations),
        relationship_ids=(),
        obligations=obligations,
        exceptions=exceptions,
        custodians=tuple(row.custodian_principal_id for row in obligations),
        scope_commitment="b" * 64,
        obligation_commitment="c" * 64,
        baseline_verifiable=True,
        baseline_reason_codes=(),
    )
    return ErasureCase(
        case_id=case_id,
        run_id="RUN-PUBLICATION-REFERENCE",
        dataset_id="DATASET-PUBLICATION",
        correlation_id=f"CORR:{case_id}",
        request_id=f"REQUEST:{case_id}",
        requester_principal_id="REQUESTER-PUBLICATION",
        root_asset_ids=graph.root_asset_ids,
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE",
        accepted_at=ACCEPTED_AT,
        phase=CasePhase.OBLIGATIONS_ACTIVE,
        revision=1,
        graph=graph,
    )


def _receipt(
    obligation: Obligation,
    receipt_id: str,
    *,
    evidence_type: str = "signature",
    disposition: str = "ERASED",
    issuer: str | None = None,
    trust_domain: str = "TD-CUSTODIAN",
    fault_domain: str = "FD-CUSTODIAN",
) -> CustodianReceipt:
    return CustodianReceipt(
        receipt_id=receipt_id,
        case_id=obligation.case_id,
        obligation_id=obligation.obligation_id,
        asset_id=obligation.asset_id,
        replica_id=obligation.replica_id,
        repository_id=obligation.repository_id,
        issuer_principal_id=issuer or obligation.custodian_principal_id,
        issuer_role="AUDITOR" if evidence_type == "audit_finding" else "CUSTODIAN",
        trust_domain=trust_domain,
        fault_domain=fault_domain,
        evidence_type=evidence_type,
        disposition=disposition,
        event_time=ACCEPTED_AT,
        submitted_at=ACCEPTED_AT,
        not_before=ACCEPTED_AT,
        provenance_refs=("PROVENANCE-PUBLICATION",),
    )


def _local_scenario(
    scenario_id: str,
    fault_family: str,
    expected_closed: bool,
    case: ErasureCase,
    receipts: tuple[CustodianReceipt, ...],
    validations: Mapping[str, BackendValidation],
    faults: tuple[FaultSpec, ...] = (),
    *,
    exception_validations: tuple[ExceptionValidation, ...] = (),
    open_challenge_ids: tuple[str, ...] = (),
) -> EvaluationScenario:
    injected = FaultInjector().inject(case, receipts, validations, faults)
    return EvaluationScenario(
        scenario_id=scenario_id,
        fault_family=fault_family,
        expected_closed=expected_closed,
        case=injected.case,
        receipts=injected.receipts,
        backend=DeterministicValidationBackend(injected.validations),
        exception_validations=exception_validations,
        open_challenge_ids=open_challenge_ids,
        injected_faults=tuple(str(row) for row in injected.applied_faults),
        mutation_log=injected.mutation_log,
    )


def _simple_local(
    scenario_id: str,
    fault_family: str,
    expected_closed: bool,
    faults: tuple[FaultSpec, ...] = (),
    *,
    count: int = 2,
) -> EvaluationScenario:
    case = _case(scenario_id, count=count)
    receipts = tuple(
        _receipt(row, f"{scenario_id}:R:{index}")
        for index, row in enumerate(case.graph.obligations, start=1)
    )
    validations = {
        row.receipt_id: BackendValidation("publication-local") for row in receipts
    }
    return _local_scenario(
        scenario_id,
        fault_family,
        expected_closed,
        case,
        receipts,
        validations,
        faults,
    )


def _anchor_scenario() -> EvaluationScenario:
    scenario_id = "F-ANCHOR-CORRUPTION"
    case = _case(scenario_id, grade="E3")
    obligation = case.graph.obligations[0]
    primary = _receipt(obligation, f"{scenario_id}:PRIMARY")
    anchor = _receipt(
        obligation,
        f"{scenario_id}:ANCHOR",
        evidence_type="inclusion_proof",
        disposition="UNREACHABLE",
        issuer="TRANSPARENCY-LOG",
    )
    validations = {
        primary.receipt_id: BackendValidation("publication-local"),
        anchor.receipt_id: BackendValidation("publication-local", anchor_valid=True),
    }
    return _local_scenario(
        scenario_id,
        "evidence-integrity",
        False,
        case,
        (primary, anchor),
        validations,
        (FaultSpec(FaultKind.CORRUPT_ANCHOR, (anchor.receipt_id,)),),
    )


def _mechanism_scenario() -> EvaluationScenario:
    scenario_id = "F-MECHANISM-LOSS"
    case = _case(scenario_id, grade="E4")
    receipt = _receipt(
        case.graph.obligations[0],
        f"{scenario_id}:PRIMARY",
        evidence_type="deletion_acknowledgement",
    )
    validations = {
        receipt.receipt_id: BackendValidation(
            "publication-local",
            ordering_support_valid=True,
            mechanism_present=True,
            mechanism_valid=True,
            mechanism_expires_at=EVALUATION_TIME + timedelta(days=1),
        )
    }
    return _local_scenario(
        scenario_id,
        "evidence-capability",
        False,
        case,
        (receipt,),
        validations,
        (FaultSpec(FaultKind.DROP_MECHANISM_ATTESTATION, (receipt.receipt_id,)),),
    )


def _corroborator_scenario() -> EvaluationScenario:
    scenario_id = "F-CORRELATED-CORROBORATORS"
    case = _case(scenario_id, grade="E5")
    obligation = case.graph.obligations[0]
    primary = _receipt(
        obligation,
        f"{scenario_id}:PRIMARY",
        evidence_type="deletion_acknowledgement",
    )
    audit_1 = _receipt(
        obligation,
        f"{scenario_id}:AUDIT:1",
        evidence_type="audit_finding",
        issuer="AUDITOR-1",
        trust_domain="TD-AUDITOR-1",
        fault_domain="FD-AUDITOR-1",
    )
    audit_2 = _receipt(
        obligation,
        f"{scenario_id}:AUDIT:2",
        evidence_type="audit_finding",
        issuer="AUDITOR-2",
        trust_domain="TD-AUDITOR-2",
        fault_domain="FD-AUDITOR-2",
    )
    validations = {
        primary.receipt_id: BackendValidation(
            "publication-local",
            ordering_support_valid=True,
            mechanism_present=True,
            mechanism_valid=True,
            mechanism_expires_at=EVALUATION_TIME + timedelta(days=1),
        ),
        audit_1.receipt_id: BackendValidation("publication-local"),
        audit_2.receipt_id: BackendValidation("publication-local"),
    }
    return _local_scenario(
        scenario_id,
        "correlated-fault-domain",
        False,
        case,
        (primary, audit_1, audit_2),
        validations,
        (
            FaultSpec(
                FaultKind.COLLAPSE_CORROBORATOR_DOMAINS,
                (audit_1.receipt_id, audit_2.receipt_id),
            ),
        ),
    )


def _exception_scenario() -> EvaluationScenario:
    scenario_id = "C-VALID-EXCEPTION"
    case = _case(scenario_id, exception=True)
    exception_id = case.graph.exceptions[0].exception_id
    return _local_scenario(
        scenario_id,
        "policy-exception",
        True,
        case,
        (),
        {},
        exception_validations=(ExceptionValidation(exception_id, True, True),),
    )


def _challenge_scenario() -> EvaluationScenario:
    scenario_id = "F-OPEN-CHALLENGE"
    base = _simple_local(scenario_id, "dispute", False, count=1)
    return replace(base, open_challenge_ids=(f"{scenario_id}:CHALLENGE:1",))


def _pbft_scenario(
    scenario_id: str,
    fault_family: str,
    expected_closed: bool,
    profile: PBFTFaultProfile,
) -> EvaluationScenario:
    case = _case(scenario_id)
    receipt = _receipt(case.graph.obligations[0], f"{scenario_id}:R:1")
    validator_ids = ("VALIDATOR-1", "VALIDATOR-2", "VALIDATOR-3", "VALIDATOR-4")
    client = SimulatedPBFTClient(validator_ids, profile)
    backend = PBFTValidationBackend(client, validator_count=4, fault_tolerance=1)
    active_faults = tuple(
        key
        for key, value in asdict(profile).items()
        if value not in (False, (), [], None)
    )
    return EvaluationScenario(
        scenario_id=scenario_id,
        fault_family=fault_family,
        expected_closed=expected_closed,
        case=case,
        receipts=(receipt,),
        backend=backend,
        injected_faults=active_faults,
    )


def _builders() -> dict[str, Callable[[], EvaluationScenario]]:
    return {
        "C-CLEAN": lambda: _simple_local("C-CLEAN", "control", True),
        "F-RECEIPT-OMISSION": lambda: _simple_local(
            "F-RECEIPT-OMISSION",
            "omission",
            False,
            (FaultSpec(FaultKind.OMIT_RECEIPT, ("F-RECEIPT-OMISSION:R:2",)),),
        ),
        "F-LATE-RECEIPT": lambda: _simple_local(
            "F-LATE-RECEIPT",
            "timing",
            False,
            (FaultSpec(FaultKind.LATE_RECEIPT, ("F-LATE-RECEIPT:R:2",)),),
        ),
        "F-AUTHENTICATOR-CORRUPTION": lambda: _simple_local(
            "F-AUTHENTICATOR-CORRUPTION",
            "evidence-integrity",
            False,
            (
                FaultSpec(
                    FaultKind.CORRUPT_AUTHENTICATOR,
                    ("F-AUTHENTICATOR-CORRUPTION:R:2",),
                ),
            ),
        ),
        "F-ANCHOR-CORRUPTION": _anchor_scenario,
        "F-MECHANISM-LOSS": _mechanism_scenario,
        "F-EQUIVOCATION": lambda: _simple_local(
            "F-EQUIVOCATION",
            "equivocation",
            False,
            (
                FaultSpec(
                    FaultKind.EQUIVOCATE_DISPOSITION,
                    ("F-EQUIVOCATION:R:1",),
                ),
            ),
            count=1,
        ),
        "F-CORRELATED-CORROBORATORS": _corroborator_scenario,
        "F-BASELINE-LOSS": lambda: _simple_local(
            "F-BASELINE-LOSS",
            "scope-completeness",
            False,
            (FaultSpec(FaultKind.LOSE_AUTHENTICATED_BASELINE),),
            count=1,
        ),
        "C-VALID-EXCEPTION": _exception_scenario,
        "F-OPEN-CHALLENGE": _challenge_scenario,
        "D-BYZANTINE-WITHIN-THRESHOLD": lambda: _pbft_scenario(
            "D-BYZANTINE-WITHIN-THRESHOLD",
            "byzantine-validator",
            True,
            PBFTFaultProfile(byzantine_validator_ids=("VALIDATOR-4",)),
        ),
        "D-CRASH-WITHIN-THRESHOLD": lambda: _pbft_scenario(
            "D-CRASH-WITHIN-THRESHOLD",
            "validator-crash",
            True,
            PBFTFaultProfile(crashed_validator_ids=("VALIDATOR-4",)),
        ),
        "D-QUORUM-LOSS": lambda: _pbft_scenario(
            "D-QUORUM-LOSS",
            "validator-crash",
            False,
            PBFTFaultProfile(crashed_validator_ids=("VALIDATOR-3", "VALIDATOR-4")),
        ),
        "D-NETWORK-PARTITION": lambda: _pbft_scenario(
            "D-NETWORK-PARTITION",
            "network-partition",
            False,
            PBFTFaultProfile(partitioned_validator_ids=("VALIDATOR-3", "VALIDATOR-4")),
        ),
        "D-COMMITMENT-EQUIVOCATION": lambda: _pbft_scenario(
            "D-COMMITMENT-EQUIVOCATION",
            "certificate-equivocation",
            False,
            PBFTFaultProfile(commitment_equivocation=True),
        ),
        "D-DUPLICATE-IDENTITY": lambda: _pbft_scenario(
            "D-DUPLICATE-IDENTITY",
            "membership-integrity",
            False,
            PBFTFaultProfile(duplicate_validator_identity=True),
        ),
    }


def _load_config(path: str | Path | None) -> dict[str, object]:
    config_path = DEFAULT_CONFIG if path is None else Path(path)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    schema = json.loads(CONFIG_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    if payload.get("config_format") != "verclo.publication-campaign.v1":
        raise ValueError("unsupported publication campaign format")
    if not isinstance(payload.get("campaign_id"), str) or not payload["campaign_id"]:
        raise ValueError("publication campaign_id must be a non-empty string")
    if not isinstance(payload.get("seed"), int):
        raise TypeError("publication campaign seed must be an integer")
    if not isinstance(payload.get("scenarios"), list) or not payload["scenarios"]:
        raise ValueError("publication campaign must define scenarios")
    for row in payload["scenarios"]:
        if not isinstance(row, dict) or set(row) != {
            "scenario_id",
            "fault_family",
            "expected_closed",
        }:
            raise ValueError("each scenario requires exactly three declared fields")
        if not all(
            isinstance(row[key], str) and row[key]
            for key in ("scenario_id", "fault_family")
        ):
            raise ValueError(
                "scenario identifiers and fault families must be non-empty strings"
            )
        if not isinstance(row["expected_closed"], bool):
            raise TypeError("scenario expected_closed must be boolean")
    return payload


def build_reference_scenarios(
    config_path: str | Path | None = None,
) -> tuple[EvaluationScenario, ...]:
    config = _load_config(config_path)
    builders = _builders()
    configured_ids = [str(row["scenario_id"]) for row in config["scenarios"]]
    if len(configured_ids) != len(set(configured_ids)):
        raise ValueError("scenario identifiers must be unique")
    unknown = tuple(sorted(set(configured_ids) - set(builders)))
    if unknown:
        raise ValueError(f"campaign references unknown scenarios: {unknown}")
    scenarios = [builders[row_id]() for row_id in configured_ids]
    random.Random(int(config["seed"])).shuffle(scenarios)
    expected = {
        str(row["scenario_id"]): (
            str(row["fault_family"]),
            bool(row["expected_closed"]),
        )
        for row in config["scenarios"]
    }
    for scenario in scenarios:
        declared = expected[scenario.scenario_id]
        if declared != (scenario.fault_family, scenario.expected_closed):
            raise ValueError(f"scenario metadata mismatch: {scenario.scenario_id}")
    return tuple(scenarios)


def _metrics(rows: list[dict[str, object]]) -> dict[str, object]:
    true_positive = sum(
        bool(row["expected_closed"]) and bool(row["accepted_closed"]) for row in rows
    )
    true_negative = sum(
        not bool(row["expected_closed"]) and not bool(row["accepted_closed"])
        for row in rows
    )
    false_positive = sum(
        not bool(row["expected_closed"]) and bool(row["accepted_closed"])
        for row in rows
    )
    false_negative = sum(
        bool(row["expected_closed"]) and not bool(row["accepted_closed"])
        for row in rows
    )
    positive = true_positive + false_negative
    negative = true_negative + false_positive
    total = len(rows)
    true_positive_rate = true_positive / positive if positive else 0.0
    true_negative_rate = true_negative / negative if negative else 0.0
    return {
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "accuracy": round((true_positive + true_negative) / total, 6),
        "balanced_accuracy": round((true_positive_rate + true_negative_rate) / 2, 6),
        "false_acceptance_rate": round(false_positive / negative, 6)
        if negative
        else 0.0,
        "false_rejection_rate": round(false_negative / positive, 6)
        if positive
        else 0.0,
    }


def run_reference_campaign(config_path: str | Path | None = None) -> CampaignReport:
    config = _load_config(config_path)
    scenarios = build_reference_scenarios(config_path)
    comparator = PolicyComparator()
    results: list[dict[str, object]] = []
    metric_rows: dict[str, list[dict[str, object]]] = {
        str(policy): [] for policy in ComparisonPolicy
    }
    for scenario in scenarios:
        decisions = comparator.evaluate(
            scenario.case,
            scenario.receipts,
            EVALUATION_TIME,
            scenario.backend,
            exception_validations=scenario.exception_validations,
            open_challenge_ids=scenario.open_challenge_ids,
        )
        decision_payload: dict[str, object] = {}
        for decision in decisions:
            row = {
                "expected_closed": scenario.expected_closed,
                "accepted_closed": decision.accepted_closed,
            }
            metric_rows[str(decision.policy)].append(row)
            decision_payload[str(decision.policy)] = {
                "accepted_closed": decision.accepted_closed,
                "correct": decision.accepted_closed == scenario.expected_closed,
                "raw_decision": decision.raw_decision,
                "reason_codes": list(decision.reason_codes),
            }
        results.append(
            {
                "scenario_id": scenario.scenario_id,
                "fault_family": scenario.fault_family,
                "expected_closed": scenario.expected_closed,
                "injected_faults": list(scenario.injected_faults),
                "mutation_log": list(scenario.mutation_log),
                "decisions": decision_payload,
            }
        )
    payload: dict[str, object] = {
        "report_format": "verclo.publication-campaign-report.v1",
        "campaign_id": str(config["campaign_id"]),
        "campaign_config_sha256": hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "seed": int(config["seed"]),
        "model_version": "PAE-FECM-v1.0.0",
        "protocol_version": "C-PAE-1.0.0",
        "evaluation_time": EVALUATION_TIME.isoformat().replace("+00:00", "Z"),
        "scenario_count": len(scenarios),
        "fault_families": sorted({row.fault_family for row in scenarios}),
        "policies": [str(row) for row in ComparisonPolicy],
        "metrics": {
            policy: _metrics(rows) for policy, rows in sorted(metric_rows.items())
        },
        "results": results,
        "limitations": [
            "DETERMINISTIC_FAULT_MATRIX_NOT_STATISTICAL_INFERENCE",
            "PBFT_CERTIFICATE_BOUNDARY_NOT_NETWORK_OR_CONSENSUS_IMPLEMENTATION",
            "CLOSURE_RELATIVE_TO_AUTHENTICATED_OBSERVABLE_SCOPE",
            "NO_PHYSICAL_DESTRUCTION_INFERENCE",
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    payload["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    report_schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(report_schema).validate(payload)
    return CampaignReport(payload)
