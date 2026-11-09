"""TPDS extension study for PBFT view change, durability, load and scale."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import math
import platform
import statistics
import tempfile
import time
import uuid
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable

from evidence.models import BackendValidation
from proof import NetworkFaultProfile, NetworkPBFTClient, NetworkPBFTCluster, PBFTValidationBackend

from .network_study import EVALUATION_TIME, _fixture


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda v: v.isoformat()).encode("utf-8")


def _decode_key(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


@dataclass(frozen=True)
class ExtensionStudyConfig:
    concurrency_levels: tuple[int, ...] = (1, 4, 16)
    operations_per_level: int = 24
    committee_sizes: tuple[int, ...] = (4, 7, 10)
    timeout_seconds: float = 3.0
    delivery_strategy: str = "serial"

    def __post_init__(self) -> None:
        if self.delivery_strategy not in {"serial", "parallel_all", "certificate_frontier"}:
            raise ValueError("unknown delivery strategy")
        if not self.concurrency_levels or min(self.concurrency_levels) < 1:
            raise ValueError("concurrency levels must be positive")
        if self.operations_per_level < max(self.concurrency_levels):
            raise ValueError("operations must cover the largest concurrency level")
        if not self.committee_sizes or any(size < 4 or (size - 1) % 3 for size in self.committee_sizes):
            raise ValueError("committee sizes must satisfy n = 3f + 1 with f >= 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout must be positive")


def _run_load(
    backend: PBFTValidationBackend,
    label: str,
    concurrency: int,
    operations: int,
) -> dict[str, object]:
    receipt, obligation = _fixture()

    def operation(index: int) -> dict[str, object]:
        started = time.perf_counter_ns()
        request_receipt = replace(receipt, receipt_id=f"P13-EXT:{label}:{index}")
        result = None
        error = None
        # The client properties are thread-local. Capture them before returning
        # from this worker, including failed calls instead of dropping a cell.
        try:
            result = backend.validate(request_receipt, obligation, EVALUATION_TIME)
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
        certificate = backend.client.last_certificate
        return {
            "operation_id": f"{label}:{index}",
            "accepted": result.verification_material_available if result else False,
            "latency_ns": time.perf_counter_ns() - started,
            "receipt": asdict(request_receipt), "obligation": asdict(obligation),
            "evaluation_time": EVALUATION_TIME.isoformat(),
            "validation": asdict(result) if result else None,
            "certificate": asdict(certificate) if certificate else None,
            "cost": dict(backend.client.last_cost), "error": error,
            "public_keys": {k: base64.urlsafe_b64encode(v).rstrip(b"=").decode()
                for k, v in backend.client.public_keys.items()},
            "expected_epoch": backend.client.membership_epoch,
        }

    started = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        outcomes = list(executor.map(operation, range(operations)))
    elapsed = time.perf_counter_ns() - started
    latencies = [row["latency_ns"] for row in outcomes]
    return {
        "label": label,
        "operation_records": outcomes,
        "concurrency": concurrency,
        "operations": operations,
        "accepted": sum(row["accepted"] for row in outcomes),
        "success_rate": sum(row["accepted"] for row in outcomes) / operations,
        "elapsed_ns": elapsed,
        "throughput_ops_per_second": operations / (elapsed / 1_000_000_000),
        "latency_median_ns": int(statistics.median(latencies)),
        "latency_p95_ns": _percentile(latencies, 0.95),
    }


def _validator_ids(size: int) -> tuple[str, ...]:
    return tuple(f"VALIDATOR-{index:02d}" for index in range(1, size + 1))


def run_local_extension_study(
    config: ExtensionStudyConfig | None = None,
) -> dict[str, object]:
    """Run infrastructure-independent extension tests on one host."""

    config = config or ExtensionStudyConfig()
    receipt, obligation = _fixture()
    decision = BackendValidation(
        "p13-extension-validator", anchor_valid=True, ordering_support_valid=True
    )

    campaign_epoch = "P13-v2-" + str(uuid.uuid4())
    validator_ids = _validator_ids(4)
    leader_fault = NetworkFaultProfile(crashed_validator_ids=(validator_ids[0],))
    with NetworkPBFTCluster(
        validator_ids, decision, membership_epoch=campaign_epoch+":view-change", fault_profile=leader_fault
    ) as cluster:
        backend = cluster.backend(timeout=config.timeout_seconds, delivery_strategy=config.delivery_strategy)
        result = backend.validate(receipt, obligation, EVALUATION_TIME)
        view_change = {
            "accepted": result.verification_material_available,
            "final_view": backend.client.last_cost["view"],
            "view_change_votes": backend.client.last_cost["view_change_votes"],
            "commit_votes": backend.client.last_cost["commit_votes"],
            "messages_sent": backend.client.last_cost["messages_sent"],
        }

    with tempfile.TemporaryDirectory(prefix="verclo-p13-recovery-") as state_root:
        with NetworkPBFTCluster(
            validator_ids, decision, membership_epoch=campaign_epoch+":recovery", persistent_root=state_root
        ) as cluster:
            first_backend = cluster.backend(timeout=config.timeout_seconds, delivery_strategy=config.delivery_strategy)
            first = first_backend.validate(receipt, obligation, EVALUATION_TIME)
            first_sequence = first_backend.client.last_cost["sequence"]
        with NetworkPBFTCluster(
            validator_ids, decision, membership_epoch=campaign_epoch+":recovery", persistent_root=state_root
        ) as restarted:
            second_backend = restarted.backend(timeout=config.timeout_seconds, delivery_strategy=config.delivery_strategy)
            second = second_backend.validate(
                replace(receipt, receipt_id="P13-EXT:RECOVERY:2"),
                obligation,
                EVALUATION_TIME,
            )
            second_sequence = second_backend.client.last_cost["sequence"]
            replica_state = [
                service._server.service.state.summary()  # type: ignore[attr-defined]
                for service in restarted.services.values()
            ]
        recovery = {
            "accepted_before_restart": first.verification_material_available,
            "accepted_after_restart": second.verification_material_available,
            "sequence_before_restart": first_sequence,
            "sequence_after_restart": second_sequence,
            "replica_state": replica_state,
        }

    committee_results: list[dict[str, object]] = []
    for size in config.committee_sizes:
        ids = _validator_ids(size)
        with NetworkPBFTCluster(ids, decision, membership_epoch=campaign_epoch+f":committee-{size}") as cluster:
            backend = cluster.backend(timeout=config.timeout_seconds, delivery_strategy=config.delivery_strategy)
            started = time.perf_counter_ns()
            result = backend.validate(
                replace(receipt, receipt_id=f"P13-EXT:COMMITTEE:{size}"),
                obligation,
                EVALUATION_TIME,
            )
            elapsed = time.perf_counter_ns() - started
            committee_results.append(
                {
                    "committee_size": size,
                    "fault_tolerance": (size - 1) // 3,
                    "quorum": 2 * ((size - 1) // 3) + 1,
                    "accepted": result.verification_material_available,
                    "latency_ns": elapsed,
                    "messages_sent": backend.client.last_cost["messages_sent"],
                    "commit_votes": backend.client.last_cost["commit_votes"],
                }
            )

    load_results: list[dict[str, object]] = []
    with NetworkPBFTCluster(validator_ids, decision, membership_epoch=campaign_epoch+":load") as cluster:
        backend = cluster.backend(timeout=config.timeout_seconds, delivery_strategy=config.delivery_strategy)
        for concurrency in config.concurrency_levels:
            load_results.append(
                _run_load(
                    backend,
                    f"local-c{concurrency}",
                    concurrency,
                    config.operations_per_level,
                )
            )

    payload: dict[str, object] = {
        "study_format": "verclo.p13-extension-study.v2",
        "study_id": "P13-TPDS-EXTENSION-LOCAL-v2",
        "scope": "single-host functional and load qualification",
        "config": asdict(config),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "transport": "HTTP over TCP loopback",
            "durable_store": "SQLite WAL synchronous FULL",
        },
        "authenticated_view_change": view_change,
        "durable_recovery": recovery,
        "committee_results": committee_results,
        "load_results": load_results,
        "claims": {
            "supported": [
                "authenticated view change replaces a failed leader within the configured bound",
                "replica proposal and commit state survives process restart",
                "client sequence allocation survives process restart",
                "the implementation accepts concurrent requests at the measured local levels",
                "the implementation forms valid certificates for the measured committee sizes",
            ],
            "excluded": [
                "multi-host LAN or WAN performance until the remote protocol is executed",
                "production operations, key custody, denial-of-service resistance or unbounded faults",
            ],
        },
    }
    failures = []
    if not view_change["accepted"] or int(view_change["final_view"]) < 1:
        failures.append("authenticated view change failed")
    if not recovery["accepted_before_restart"] or not recovery["accepted_after_restart"]:
        failures.append("durable restart recovery failed")
    if int(recovery["sequence_after_restart"]) <= int(recovery["sequence_before_restart"]):
        failures.append("durable client sequence did not advance")
    if not all(bool(row["accepted"]) for row in committee_results):
        failures.append("committee-size study failed")
    if not all(float(row["success_rate"]) == 1.0 for row in load_results):
        failures.append("concurrent load study failed")
    payload["status"] = "FAIL" if failures else "PASS"
    payload["failures"] = failures
    payload = json.loads(_canonical(payload))
    payload["study_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload


def run_remote_extension_study(
    topology_path: str | Path,
    config: ExtensionStudyConfig | None = None,
) -> dict[str, object]:
    """Run the same concurrent workload against independently deployed nodes."""

    config = config or ExtensionStudyConfig()
    topology = json.loads(Path(topology_path).read_text(encoding="utf-8"))
    decision = BackendValidation(
        "p13-remote-validator",
        anchor_valid=True,
        ordering_support_valid=True,
    )
    public_keys = {
        validator_id: _decode_key(value)
        for validator_id, value in topology["public_keys"].items()
    }
    client = NetworkPBFTClient(
        topology["endpoints"],
        public_keys,
        topology["membership_epoch"],
        decision,
        timeout=config.timeout_seconds,
        state_path=topology.get("client_state_path"),
        delivery_strategy=config.delivery_strategy,
    )
    backend = PBFTValidationBackend(
        client,
        validator_count=len(public_keys),
        fault_tolerance=(len(public_keys) - 1) // 3,
        validator_public_keys=public_keys,
        membership_epoch=topology["membership_epoch"],
        require_signed_votes=True,
    )
    receipt, obligation = _fixture()
    probe_result = backend.validate(
        replace(receipt, receipt_id="P13-EXT:REMOTE:PROBE"),
        obligation,
        EVALUATION_TIME,
    )
    probe = {
        "accepted": probe_result.verification_material_available,
        "sequence": client.last_cost["sequence"],
        "final_view": client.last_cost["view"],
        "view_changes": client.last_cost["view_changes"],
        "commit_votes": client.last_cost["commit_votes"],
        "finalized_acks": client.last_cost["finalized_acks"],
    }
    load_results = [
        _run_load(
            backend,
            f"remote-c{concurrency}",
            concurrency,
            config.operations_per_level,
        )
        for concurrency in config.concurrency_levels
    ]
    validator_status: dict[str, object] = {}
    for validator_id, endpoint in topology["endpoints"].items():
        request = urllib.request.Request(
            endpoint.rstrip("/") + "/v2/status",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
                validator_status[validator_id] = json.loads(response.read())
        except OSError as exc:
            validator_status[validator_id] = {"error": type(exc).__name__}
    payload: dict[str, object] = {
        "study_format": "verclo.p13-extension-study.v2",
        "study_id": str(topology.get("study_id", "P13-TPDS-EXTENSION-REMOTE-v2")),
        "scope": "operator-declared remote endpoints; physical topology not independently verified",
        "config": asdict(config),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "transport": str(topology.get("transport", "operator-declared")),
            "topology_label": str(topology.get("topology_label", "unspecified")),
        },
        "committee_size": len(public_keys),
        "probe": probe,
        "load_results": load_results,
        "validator_status": validator_status,
        "claims": {
            "supported": [
                "per-operation signed certificates and failures are retained for independent verification",
                "the reported latency and throughput apply to the declared topology",
            ],
            "excluded": [
                "geographic or WAN generalisation beyond the declared topology",
                "production approval",
            ],
        },
    }
    failures = []
    if not probe["accepted"]:
        failures.append("remote PBFT probe failed")
    if not all(float(row["success_rate"]) == 1.0 for row in load_results):
        failures.append("remote concurrent load study failed")
    payload["status"] = "FAIL" if failures else "PASS"
    payload["failures"] = failures
    payload = json.loads(_canonical(payload))
    payload["study_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload


def write_extension_results(report: dict[str, object], output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tables = {
        "committee-results.csv": report.get("committee_results", []),
        "load-results.csv": report.get("load_results", []),
    }
    for name, raw_rows in tables.items():
        rows = [{k:v for k,v in row.items() if k != "operation_records"} for row in raw_rows]
        if not rows:
            continue
        with (output_path.parent / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    records = [record for row in report.get("load_results", []) for record in row["operation_records"]]
    (output_path.parent / "operation-records.jsonl").write_text(
        "".join(_canonical(record).decode() + "\n" for record in records), encoding="utf-8")
    artifacts = sorted(
        path for path in output_path.parent.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    )
    (output_path.parent / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in artifacts
        ),
        encoding="utf-8",
    )
