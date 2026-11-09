"""Validated PaEBench study contract for tasks, baselines, and transfer cases."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex


CONTRACT_SCHEMA_ID = "https://pae.local/schema/paebench-study-contract/v1"
CONTRACT_SCHEMA_FILE = "paebench-study-contract-v1.schema.json"
CONTRACT_FILE = Path("configs") / "pae_bench" / "benchmark_study_contract_v1.json"
REQUIRED_TASK_IDS = frozenset({f"PBE-T{index}" for index in range(1, 7)})
REQUIRED_EXTERNAL_BASELINES = frozenset({
    "PBE-EXT-OPA",
    "PBE-EXT-PYSHACL",
    "PBE-EXT-REKOR",
    "PBE-EXT-COMPOSITE",
})
REQUIRED_TRANSFER_CASES = frozenset({
    "PBE-XD-HEALTH-RESEARCH-WITHDRAWAL",
    "PBE-XD-SAAS-TENANT-OFFBOARDING",
    "PBE-XD-ML-TRAINING-WITHDRAWAL",
})
REQUIRED_VARIANT_CLASSES = frozenset({
    "successful_closure",
    "partial_or_unverifiable",
    "adversarial_or_disputed",
})
REQUIRED_SEALED_FIELDS = frozenset({
    "closure_ground_truth",
    "verification_status_truth",
    "variant_class",
    "attack_id",
    "expected_detection",
    "hidden_topology",
})


@dataclass(frozen=True)
class PaEBenchStudyContract:
    """One canonical, schema-valid study contract and its semantic digest."""

    payload: Mapping[str, Any]
    sha256: str
    source_path: Path


def _find_file(relative: Path) -> Path:
    start = Path(__file__).resolve()
    for candidate in (start.parent, *start.parents):
        path = candidate / relative
        if path.is_file():
            return path
    raise FileNotFoundError(f"cannot locate {relative.as_posix()} from {start}")


def _unique_ids(rows: list[Mapping[str, Any]], field: str, label: str) -> set[str]:
    values = [str(row[field]) for row in rows]
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label} identifiers")
    return set(values)


def _validate_use_case(use_case: Mapping[str, Any]) -> None:
    label = str(use_case["use_case_id"])
    actors = list(use_case["actors"])
    repositories = list(use_case["repositories"])
    assets = list(use_case["assets"])
    obligations = list(use_case["obligations"])
    variants = list(use_case["variants"])
    actor_ids = _unique_ids(actors, "actor_id", f"{label} actor")
    repository_ids = _unique_ids(repositories, "repository_id", f"{label} repository")
    asset_ids = _unique_ids(assets, "asset_id", f"{label} asset")
    _unique_ids(obligations, "obligation_id", f"{label} obligation")
    _unique_ids(variants, "variant_id", f"{label} variant")

    for repository in repositories:
        if repository["actor_id"] not in actor_ids:
            raise ValueError(f"{label}: repository has unknown actor {repository['actor_id']}")
    for asset in assets:
        if asset["repository_id"] not in repository_ids:
            raise ValueError(f"{label}: asset has unknown repository {asset['repository_id']}")
        parents = set(asset["parent_asset_ids"])
        unknown = parents - asset_ids
        if unknown or asset["asset_id"] in parents:
            raise ValueError(f"{label}: invalid asset lineage for {asset['asset_id']}")
    covered_assets: set[str] = set()
    for obligation in obligations:
        if obligation["responsible_actor_id"] not in actor_ids:
            raise ValueError(
                f"{label}: obligation has unknown actor {obligation['responsible_actor_id']}"
            )
        unknown = set(obligation["asset_ids"]) - asset_ids
        if unknown:
            raise ValueError(f"{label}: obligation has unknown assets {sorted(unknown)}")
        covered_assets.update(str(value) for value in obligation["asset_ids"])
    if covered_assets != asset_ids:
        raise ValueError(f"{label}: every asset must be covered by an obligation")
    classes = {str(variant["class"]) for variant in variants}
    if classes != REQUIRED_VARIANT_CLASSES:
        raise ValueError(f"{label}: variant classes must be exactly the required three classes")


def _validate_references(payload: Mapping[str, Any]) -> None:
    tasks = list(payload["tasks"])
    baselines = list(payload["external_baselines"])
    use_cases = list(payload["independent_use_cases"])
    tracks = list(payload["evaluation_tracks"])
    task_ids = _unique_ids(tasks, "task_id", "task")
    baseline_ids = _unique_ids(baselines, "baseline_id", "external baseline")
    use_case_ids = _unique_ids(use_cases, "use_case_id", "independent use case")
    _unique_ids(tracks, "track_id", "evaluation track")

    if task_ids != REQUIRED_TASK_IDS:
        raise ValueError(
            f"task catalog mismatch; missing={sorted(REQUIRED_TASK_IDS - task_ids)} "
            f"unexpected={sorted(task_ids - REQUIRED_TASK_IDS)}"
        )
    if baseline_ids != REQUIRED_EXTERNAL_BASELINES:
        raise ValueError(
            "external baseline catalog mismatch; "
            f"missing={sorted(REQUIRED_EXTERNAL_BASELINES - baseline_ids)} "
            f"unexpected={sorted(baseline_ids - REQUIRED_EXTERNAL_BASELINES)}"
        )
    if use_case_ids != REQUIRED_TRANSFER_CASES:
        raise ValueError(
            f"transfer-case catalog mismatch; missing={sorted(REQUIRED_TRANSFER_CASES - use_case_ids)} "
            f"unexpected={sorted(use_case_ids - REQUIRED_TRANSFER_CASES)}"
        )

    sealed_fields = set(payload["oracle_boundary"]["sealed_fields"])
    if not REQUIRED_SEALED_FIELDS.issubset(sealed_fields):
        raise ValueError("oracle boundary omits required evaluator-only fields")
    for task in tasks:
        if not task["metrics"] or not any(metric["primary"] for metric in task["metrics"]):
            if task["task_id"] != "PBE-T6":
                raise ValueError(f"{task['task_id']}: at least one primary metric is required")
        prohibited = " ".join(task["prohibited_inputs"]).lower()
        if not any(token in prohibited for token in ("truth", "oracle", "sealed", "hidden", "attack")):
            raise ValueError(f"{task['task_id']}: prohibited inputs do not state an oracle boundary")
    for baseline in baselines:
        unknown = set(baseline["supported_tasks"]) - task_ids
        if unknown:
            raise ValueError(f"{baseline['baseline_id']}: unknown supported tasks {sorted(unknown)}")
        if any(upstream["version_pin"] == "latest" for upstream in baseline["upstream"]):
            raise ValueError(f"{baseline['baseline_id']}: floating 'latest' version is forbidden")
    for use_case in use_cases:
        _validate_use_case(use_case)
    permitted_case_sets = use_case_ids | {
        "PaEBench-v1.0 canonical cases",
        "PaEBench-v1.0 adversarial pairs",
    }
    for track in tracks:
        unknown_tasks = set(track["task_ids"]) - task_ids
        unknown_cases = set(track["case_sets"]) - permitted_case_sets
        if unknown_tasks or unknown_cases:
            raise ValueError(
                f"{track['track_id']}: unknown tasks={sorted(unknown_tasks)} "
                f"unknown case sets={sorted(unknown_cases)}"
            )


def load_benchmark_study_contract(
    path: str | Path | None = None,
    *,
    schema_path: str | Path | None = None,
) -> PaEBenchStudyContract:
    """Load and semantically validate the working PaEBench study contract."""

    source = Path(path).resolve() if path is not None else _find_file(CONTRACT_FILE)
    schema_source = (
        Path(schema_path).resolve()
        if schema_path is not None
        else _find_file(Path("schemas") / CONTRACT_SCHEMA_FILE)
    )
    schema = json.loads(schema_source.read_text(encoding="utf-8"))
    if schema.get("$id") != CONTRACT_SCHEMA_ID:
        raise ValueError("unexpected PaEBench study-contract schema identifier")
    Draft202012Validator.check_schema(schema)
    payload = json.loads(source.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)
    _validate_references(payload)
    return PaEBenchStudyContract(
        payload=payload,
        sha256=sha256_hex(canonical_json_bytes(payload)),
        source_path=source,
    )

