"""Bounded parallel execution and deterministic trusted-local checkpoints."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import hashlib
import os
from pathlib import Path
import pickle
import platform
import re
import sys
from typing import Any, Mapping

from htgl_dataset_generator.artifacts.canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
)
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.seeds import canonical_records_digest


CHECKPOINT_FORMAT = "htgl.deterministic-checkpoint.v1"
CHECKPOINT_OWNER_FORMAT = "htgl.checkpoint-owner.v1"
DEFAULT_MEMORY_BUDGET_BYTES = 2 * 1024**3
DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW = 16_384
MINIMUM_REPLICATE_WORKING_SET_BYTES = 64 * 1024**2
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._-]+$")


class ParallelExecutionError(RuntimeError):
    """Raised when bounded parallel execution cannot satisfy its contract."""


class CheckpointIntegrityError(ParallelExecutionError):
    """Raised when a checkpoint is unowned, incompatible, or digest-invalid."""


@dataclass(frozen=True)
class ParallelExecutionPolicy:
    """Non-semantic operational bounds for full-replicate execution."""

    worker_count: int = 1
    max_in_flight: int | None = None
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES
    estimated_bytes_per_materialized_row: int = (
        DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW
    )
    backend: str = "thread"


@dataclass(frozen=True)
class ExecutionCapacity:
    requested_worker_count: int
    effective_worker_count: int
    max_in_flight: int
    memory_budget_bytes: int
    estimated_replicate_working_set_bytes: int
    backend: str
    backpressure_active: bool


def resolve_execution_capacity(
    resolved: ResolvedConfig,
    policy: ParallelExecutionPolicy,
    *,
    task_count: int,
) -> ExecutionCapacity:
    """Resolve deterministic concurrency from explicit limits and materialized n."""

    if policy.worker_count < 1:
        raise ParallelExecutionError("worker_count must be positive")
    if policy.max_in_flight is not None and policy.max_in_flight < 1:
        raise ParallelExecutionError("max_in_flight must be positive when supplied")
    if policy.memory_budget_bytes < MINIMUM_REPLICATE_WORKING_SET_BYTES:
        raise ParallelExecutionError(
            "memory_budget_bytes must be at least 64 MiB for one bounded replicate"
        )
    if policy.estimated_bytes_per_materialized_row < 1:
        raise ParallelExecutionError(
            "estimated_bytes_per_materialized_row must be positive"
        )
    if policy.backend not in {"serial", "thread"}:
        raise ParallelExecutionError("parallel backend must be 'serial' or 'thread'")
    if task_count < 0:
        raise ParallelExecutionError("task_count cannot be negative")

    estimated = max(
        MINIMUM_REPLICATE_WORKING_SET_BYTES,
        resolved.claim_scale.materialized_row_target
        * policy.estimated_bytes_per_materialized_row,
    )
    memory_slots = policy.memory_budget_bytes // estimated
    if memory_slots < 1:
        raise ParallelExecutionError(
            "one configured replicate exceeds the declared memory budget: "
            f"estimated={estimated} budget={policy.memory_budget_bytes}; reduce n, "
            "raise the explicit budget, or use a smaller materialization condition"
        )
    requested_in_flight = policy.max_in_flight or policy.worker_count
    effective = min(
        policy.worker_count,
        requested_in_flight,
        int(memory_slots),
        max(task_count, 1),
    )
    if policy.backend == "serial":
        effective = 1
    return ExecutionCapacity(
        requested_worker_count=policy.worker_count,
        effective_worker_count=effective,
        max_in_flight=effective,
        memory_budget_bytes=policy.memory_budget_bytes,
        estimated_replicate_working_set_bytes=estimated,
        backend=policy.backend,
        backpressure_active=(effective < min(policy.worker_count, max(task_count, 1))),
    )


class DeterministicCheckpointStore:
    """Persist digest-verified checkpoints for trusted local resume only."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        resolved: ResolvedConfig,
        namespace: str,
    ) -> None:
        if not namespace or _SAFE_TOKEN.fullmatch(namespace) is None:
            raise CheckpointIntegrityError(
                "checkpoint namespace must use only letters, digits, dot, underscore, or hyphen"
            )
        self.root = Path(root).resolve()
        self.resolved = resolved
        self.namespace = namespace
        self.owner_path = self.root / ".htgl-checkpoint-owned.json"
        self.identity = {
            "format": CHECKPOINT_OWNER_FORMAT,
            "checkpoint_format": CHECKPOINT_FORMAT,
            "run_id": resolved.run.run_id,
            "config_sha256": resolved.config_sha256,
            "contract_version": resolved.run.contract_version,
            "code_version": resolved.run.code_version,
            "container_version": resolved.run.container_version,
            "namespace": namespace,
            "python_implementation": platform.python_implementation(),
            "python_cache_tag": sys.implementation.cache_tag,
            "pickle_protocol": 5,
            "trust_boundary": "generator_owned_local_state_not_an_interchange_artifact",
        }
        self._initialize_owner()

    def load(self, plan: ResolvedRunPlan) -> Any | None:
        """Load one checkpoint only after owner, byte, and semantic verification."""

        self._verify_owner()
        payload_path, manifest_path = self._paths(plan)
        if not payload_path.exists() and not manifest_path.exists():
            return None
        if not payload_path.is_file() or not manifest_path.is_file():
            raise CheckpointIntegrityError(
                f"checkpoint is partial for scenario={plan.scenario_id} replicate={plan.replicate_id}"
            )
        manifest = _read_json_object(manifest_path)
        expected_identity = self._manifest_identity(plan)
        disagreements = {
            key: {"expected": value, "observed": manifest.get(key)}
            for key, value in expected_identity.items()
            if manifest.get(key) != value
        }
        if disagreements:
            raise CheckpointIntegrityError(
                f"checkpoint identity mismatch for {manifest_path}: {disagreements}"
            )
        payload = payload_path.read_bytes()
        if len(payload) != manifest.get("payload_bytes"):
            raise CheckpointIntegrityError(
                f"checkpoint payload length mismatch for {payload_path}"
            )
        digest = hashlib.sha256(payload).hexdigest()
        if digest != manifest.get("payload_sha256"):
            raise CheckpointIntegrityError(
                f"checkpoint payload digest mismatch for {payload_path}"
            )
        try:
            result = pickle.loads(payload)
        except Exception as exc:
            raise CheckpointIntegrityError(
                f"checkpoint payload cannot be reconstructed: {exc}"
            ) from exc
        semantic_digest = checkpoint_semantic_digest(result)
        if semantic_digest != manifest.get("semantic_digest"):
            raise CheckpointIntegrityError(
                f"checkpoint semantic digest mismatch for {payload_path}"
            )
        return result

    def save(self, plan: ResolvedRunPlan, result: Any) -> None:
        """Write one checkpoint atomically and prove stable serialization locally."""

        self._verify_owner()
        payload_path, manifest_path = self._paths(plan)
        payload_path.parent.mkdir(parents=True, exist_ok=True)
        first = pickle.dumps(result, protocol=5)
        second = pickle.dumps(result, protocol=5)
        if first != second:
            raise CheckpointIntegrityError(
                "checkpoint serialization is not byte-deterministic for the current result"
            )
        manifest = {
            **self._manifest_identity(plan),
            "payload_bytes": len(first),
            "payload_sha256": hashlib.sha256(first).hexdigest(),
            "semantic_digest": checkpoint_semantic_digest(result),
        }
        if payload_path.exists() or manifest_path.exists():
            existing = self.load(plan)
            if checkpoint_semantic_digest(existing) != manifest["semantic_digest"]:
                raise CheckpointIntegrityError(
                    "existing checkpoint differs from newly completed deterministic result"
                )
            return
        atomic_write_bytes(payload_path, first)
        atomic_write_bytes(manifest_path, canonical_json_bytes(manifest))

    def contains(self, plan: ResolvedRunPlan) -> bool:
        payload, manifest = self._paths(plan)
        return payload.exists() or manifest.exists()

    def _initialize_owner(self) -> None:
        if self.root.exists():
            if not self.root.is_dir():
                raise CheckpointIntegrityError(
                    f"checkpoint root is not a directory: {self.root}"
                )
            if any(self.root.iterdir()) and not self.owner_path.is_file():
                raise CheckpointIntegrityError(
                    f"refusing non-empty unowned checkpoint root {self.root}"
                )
        else:
            self.root.mkdir(parents=True)
        if self.owner_path.exists():
            self._verify_owner()
        else:
            atomic_write_bytes(self.owner_path, canonical_json_bytes(self.identity))

    def _verify_owner(self) -> None:
        if not self.owner_path.is_file():
            raise CheckpointIntegrityError(
                f"checkpoint owner marker is missing: {self.owner_path}"
            )
        observed = _read_json_object(self.owner_path)
        if observed != self.identity:
            raise CheckpointIntegrityError(
                f"checkpoint owner identity mismatch at {self.owner_path}"
            )

    def _paths(self, plan: ResolvedRunPlan) -> tuple[Path, Path]:
        scenario = _safe_token(plan.scenario_id)
        base = self.root / f"scenario={scenario}" / f"replicate={plan.replicate_id:06d}"
        return base.with_suffix(".pickle"), base.with_suffix(".manifest.json")

    def _manifest_identity(self, plan: ResolvedRunPlan) -> Mapping[str, Any]:
        return {
            **self.identity,
            "format": CHECKPOINT_FORMAT,
            "scenario_id": plan.scenario_id,
            "replicate_id": plan.replicate_id,
        }


def checkpoint_semantic_digest(result: Any) -> str:
    """Bind a checkpoint to authoritative rows when the result exposes them."""

    output = getattr(result, "output", None)
    artifacts = output.get("artifacts") if isinstance(output, Mapping) else None
    table_records = getattr(artifacts, "authoritative_table_records", None)
    if callable(table_records):
        tables = table_records()
        return domain_sha256(
            "checkpoint-authoritative-table-digests-v1",
            {
                table_name: canonical_records_digest(rows)
                for table_name, rows in sorted(tables.items())
            },
        )
    return domain_sha256(
        "checkpoint-generic-result-v1",
        _checkpoint_plain(result),
    )


def _checkpoint_plain(value: Any) -> Any:
    if is_dataclass(value):
        return _checkpoint_plain(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): _checkpoint_plain(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_checkpoint_plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_checkpoint_plain(item) for item in value), key=repr)
    return value


def _read_json_object(path: Path) -> dict[str, Any]:
    import json

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CheckpointIntegrityError(f"cannot read checkpoint JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CheckpointIntegrityError(f"checkpoint JSON must be an object: {path}")
    return value


def _safe_token(value: str) -> str:
    if not value or _SAFE_TOKEN.fullmatch(value) is None:
        raise CheckpointIntegrityError(f"unsafe checkpoint identity token {value!r}")
    return value
