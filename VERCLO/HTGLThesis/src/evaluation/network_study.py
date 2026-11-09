"""P13 network trust-anchor experiment and backend cost comparison."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import statistics
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from jsonschema import Draft202012Validator
from evidence.models import BackendValidation, CustodianReceipt
from proof import (
    DeterministicValidationBackend,
    NetworkFaultProfile,
    NetworkMerkleValidationBackend,
    NetworkPBFTCluster,
    NetworkSignedValidationBackend,
    serve_merkle_authority,
    serve_signed_authority,
)
from verclo.models import Obligation


UTC = timezone.utc
EVENT_TIME = datetime(2026, 9, 23, tzinfo=UTC)
EVALUATION_TIME = EVENT_TIME + timedelta(seconds=1)
VALIDATORS = ("VALIDATOR-1", "VALIDATOR-2", "VALIDATOR-3", "VALIDATOR-4")
REPORT_SCHEMA = (
    Path(__file__).resolve().parent
    / "configs"
    / "p13_network_study_v2.schema.json"
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class NetworkStudyConfig:
    repetitions: int = 15
    warmups: int = 3
    timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.repetitions < 3 or self.warmups < 0:
            raise ValueError("network study requires >=3 repetitions and non-negative warmups")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


def _fixture() -> tuple[CustodianReceipt, Obligation]:
    obligation = Obligation(
        obligation_id="P13:OBLIGATION:1",
        case_id="P13:CASE:1",
        dataset_id="P13:DATASET:1",
        correlation_id="P13:CORRELATION:1",
        asset_id="P13:ASSET:1",
        replica_id="P13:REPLICA:1",
        repository_id="P13:REPOSITORY:1",
        custodian_principal_id="P13:CUSTODIAN:1",
        deadline=EVENT_TIME + timedelta(days=1),
        minimum_evidence_grade="E2",
        permitted_dispositions=("ERASED",),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE",
        policy_version="1.0.0",
    )
    receipt = CustodianReceipt(
        receipt_id="P13:RECEIPT:1",
        case_id=obligation.case_id,
        obligation_id=obligation.obligation_id,
        asset_id=obligation.asset_id,
        replica_id=obligation.replica_id,
        repository_id=obligation.repository_id,
        issuer_principal_id=obligation.custodian_principal_id,
        issuer_role="CUSTODIAN",
        trust_domain="P13:TRUST-DOMAIN:1",
        fault_domain="P13:FAULT-DOMAIN:1",
        evidence_type="signature",
        disposition="ERASED",
        event_time=EVENT_TIME,
        submitted_at=EVENT_TIME,
        not_before=EVENT_TIME,
        provenance_refs=("P13:PROVENANCE:1",),
    )
    return receipt, obligation


def _percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def _measure(
    backend_name: str,
    validate: Callable[[], tuple[BackendValidation, dict[str, int]]],
    config: NetworkStudyConfig,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    for _ in range(config.warmups):
        validate()
    rows: list[dict[str, object]] = []
    for repetition in range(config.repetitions):
        started = time.perf_counter_ns()
        result, cost = validate()
        elapsed = time.perf_counter_ns() - started
        rows.append(
            {
                "backend": backend_name,
                "repetition": repetition,
                "accepted": result.verification_material_available,
                "latency_ns": elapsed,
                "messages_sent": int(cost.get("messages_sent", 0)),
                "request_bytes": int(cost.get("request_bytes", 0)),
                "response_bytes": int(cost.get("response_bytes", 0)),
            }
        )
    latencies = [int(row["latency_ns"]) for row in rows]
    return (
        {
            "backend": backend_name,
            "repetitions": len(rows),
            "success_rate": sum(bool(row["accepted"]) for row in rows) / len(rows),
            "latency_median_ns": int(statistics.median(latencies)),
            "latency_p95_ns": _percentile(latencies, 0.95),
            "messages_median": int(statistics.median(int(row["messages_sent"]) for row in rows)),
            "request_bytes_median": int(statistics.median(int(row["request_bytes"]) for row in rows)),
            "response_bytes_median": int(statistics.median(int(row["response_bytes"]) for row in rows)),
        },
        rows,
    )


def _fault_cases(timeout: float) -> list[dict[str, object]]:
    receipt, obligation = _fixture()
    decision = BackendValidation("p13-validator", anchor_valid=True, ordering_support_valid=True)
    cases = (
        ("healthy", NetworkFaultProfile(), True),
        ("one-crash", NetworkFaultProfile(crashed_validator_ids=("VALIDATOR-4",)), True),
        ("two-crashes", NetworkFaultProfile(crashed_validator_ids=("VALIDATOR-3", "VALIDATOR-4")), False),
        ("minority-partition", NetworkFaultProfile(partitioned_validator_ids=("VALIDATOR-4",)), True),
        ("quorum-partition", NetworkFaultProfile(partitioned_validator_ids=("VALIDATOR-3", "VALIDATOR-4")), False),
        ("one-equivocator", NetworkFaultProfile(equivocating_validator_ids=("VALIDATOR-4",)), True),
        ("two-equivocators", NetworkFaultProfile(equivocating_validator_ids=("VALIDATOR-3", "VALIDATOR-4")), False),
        ("one-invalid-signature", NetworkFaultProfile(invalid_signature_validator_ids=("VALIDATOR-4",)), True),
        ("two-invalid-signatures", NetworkFaultProfile(invalid_signature_validator_ids=("VALIDATOR-3", "VALIDATOR-4")), False),
        ("one-conflicting-decision", NetworkFaultProfile(conflicting_decision_validator_ids=("VALIDATOR-4",)), True),
        ("two-conflicting-decisions", NetworkFaultProfile(conflicting_decision_validator_ids=("VALIDATOR-3", "VALIDATOR-4")), False),
    )
    rows: list[dict[str, object]] = []
    for scenario_id, profile, expected in cases:
        with NetworkPBFTCluster(VALIDATORS, decision, fault_profile=profile, membership_epoch="P13-v2-fault-" + str(uuid.uuid4())) as cluster:
            backend = cluster.backend(timeout=timeout)
            result = backend.validate(receipt, obligation, EVALUATION_TIME)
            cost = dict(backend.client.last_cost)
        accepted = result.verification_material_available
        rows.append(
            {
                "scenario_id": scenario_id,
                "fault_profile": {key: list(value) for key, value in asdict(profile).items()},
                "expected_accepted": expected,
                "accepted": accepted,
                "correct": accepted == expected,
                "diagnostics": list(result.diagnostics),
                "prepare_votes": int(cost.get("prepare_votes", 0)),
                "commit_votes": int(cost.get("commit_votes", 0)),
                "messages_sent": int(cost.get("messages_sent", 0)),
            }
        )
    return rows


def run_network_backend_study(config: NetworkStudyConfig | None = None) -> dict[str, object]:
    """Execute TCP backends, PBFT fault cases and a common-operation benchmark."""

    config = config or NetworkStudyConfig()
    receipt, obligation = _fixture()
    decision = BackendValidation("p13-validator", anchor_valid=True, ordering_support_valid=True)
    observations: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []

    local = DeterministicValidationBackend({receipt.receipt_id: decision})
    summary, rows = _measure(
        "deterministic-local-v1",
        lambda: (local.validate(receipt, obligation, EVALUATION_TIME), {"messages_sent": 0}),
        config,
    )
    summaries.append(summary)
    observations.extend(rows)

    signed_service, signed_key = serve_signed_authority("P13-AUTHORITY", decision)
    with signed_service:
        signed = NetworkSignedValidationBackend(
            signed_service.url,
            "P13-AUTHORITY",
            signed_key,
            timeout=config.timeout_seconds,
        )
        summary, rows = _measure(
            signed.name,
            lambda: (signed.validate(receipt, obligation, EVALUATION_TIME), dict(signed.last_cost)),
            config,
        )
        summaries.append(summary)
        observations.extend(rows)

    merkle_service, merkle_key = serve_merkle_authority("P13-MERKLE", decision)
    with merkle_service:
        merkle = NetworkMerkleValidationBackend(
            merkle_service.url,
            "P13-MERKLE",
            merkle_key,
            timeout=config.timeout_seconds,
        )
        summary, rows = _measure(
            merkle.name,
            lambda: (merkle.validate(receipt, obligation, EVALUATION_TIME), dict(merkle.last_cost)),
            config,
        )
        summaries.append(summary)
        observations.extend(rows)

    with NetworkPBFTCluster(VALIDATORS, decision, membership_epoch="P13-v2-cost-" + str(uuid.uuid4())) as cluster:
        pbft = cluster.backend(timeout=config.timeout_seconds)
        summary, rows = _measure(
            "network-pbft-4f1-v2",
            lambda: (pbft.validate(receipt, obligation, EVALUATION_TIME), dict(pbft.client.last_cost)),
            config,
        )
        summaries.append(summary)
        observations.extend(rows)

    fault_cases = _fault_cases(config.timeout_seconds)
    payload: dict[str, object] = {
        "study_format": "verclo.p13-network-study.v2",
        "study_id": "P13-REPLACEABLE-TRUST-ANCHORS-v2",
        "config": asdict(config),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "transport": "HTTP/1.1 over TCP loopback",
            "cryptography": "Ed25519/SHA-256",
        },
        "backends": summaries,
        "observations": observations,
        "fault_cases": fault_cases,
        "claims": {
            "supported": [
                "all backends implement the same ReceiptValidationBackend operation",
                "PBFT certificates are formed by PRE-PREPARE, PREPARE and COMMIT exchanges over TCP",
                "signed commit votes are verified against an epoch-bound membership",
                "the measured cost comparison applies to this host and registered configuration",
            ],
            "excluded": [
                "wide-area or Internet latency",
                "unbounded Byzantine tolerance",
                "physical erasure inference",
                "production key custody or denial-of-service resistance",
            ],
        },
    }
    canonical = _canonical(payload)
    payload["study_sha256"] = hashlib.sha256(canonical).hexdigest()
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    if not all(bool(row["correct"]) for row in fault_cases):
        raise AssertionError("one or more PBFT fault cases violated its registered expectation")
    if not all(float(row["success_rate"]) == 1.0 for row in summaries):
        raise AssertionError("one or more clean backends failed validation")
    return payload
