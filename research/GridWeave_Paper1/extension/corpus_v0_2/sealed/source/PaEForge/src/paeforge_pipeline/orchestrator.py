"""One-command PaEGen-to-VERCLO-to-PaEBench vertical orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback
from types import SimpleNamespace
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from paeforge_contract import read_verifier_bundle, validate_document, write_verifier_bundle
from paeforge_contract.canonical import canonical_json_bytes, sha256_digest
from paeforge_contract.evaluator import build_evaluation_report

from .io import (
    StructuredRunLog,
    artifact_inventory,
    read_json,
    runtime_identity,
    source_identity,
    utc_now,
    write_json,
)
from .projection import build_projection, translated_policy


PIPELINE_VERSION = "1.0.0"


@dataclass(frozen=True)
class PipelineResult:
    run_id: str
    run_root: Path
    manifest_path: Path
    result_path: Path
    evaluation_path: Path
    metrics_path: Path


def _resolve(base: Path, value: str) -> Path:
    path = Path(value)
    resolved = (base / path).resolve() if not path.is_absolute() else path.resolve()
    if not resolved.exists() and "DatasetGenerator" in resolved.parts:
        parts = list(resolved.parts)
        for index, part in enumerate(parts):
            if part == "DatasetGenerator":
                candidate = Path(*parts[:index], "GridWeave", *parts[index + 1:])
                if candidate.exists():
                    return candidate
    return resolved


def _load_config(path: Path) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    schema_files = {
        "1.0.0": "pipeline-config-v1.schema.json",
        "1.1.0": "pipeline-config-v1.1.schema.json",
        "1.2.0": "pipeline-config-v1.2.schema.json",
    }
    schema_version = str(payload.get("schema_version", ""))
    if schema_version not in schema_files:
        raise ValueError(f"unsupported pipeline configuration schema_version: {schema_version}")
    schema_path = path.parent / schema_files[schema_version]
    if not schema_path.is_file():
        schema_path = Path(__file__).resolve().parents[2] / "configs" / schema_files[schema_version]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    return payload


def _default_run_id(config: Mapping[str, Any]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(canonical_json_bytes(config)).hexdigest()[:10]
    return f"{config['run_label']}-{timestamp}-{digest}"


def _safe_run_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise ValueError("run_id must contain only letters, digits, dot, underscore, and hyphen")
    return value


def _ensure_external_output(output_root: Path, source_roots: tuple[Path, ...]) -> None:
    for source_root in source_roots:
        if output_root == source_root or output_root.is_relative_to(source_root):
            raise ValueError(f"run output root must be outside source tree: {source_root}")


def _select_paegen_replica(build: Any, variant_id: str) -> Any:
    matches = [
        replica for replica in build.replicas
        if replica.ground_truth.payload.get("variant_id") == variant_id
    ]
    if len(matches) != 1:
        available = sorted(
            str(replica.ground_truth.payload.get("variant_id")) for replica in build.replicas
        )
        raise ValueError(f"PaEGen variant {variant_id!r} not found exactly once; available={available}")
    return matches[0]


def run_pipeline(
    config_path: str | Path,
    *,
    run_id: str | None = None,
    output_root: str | Path | None = None,
) -> PipelineResult:
    """Execute all vertical stages and return only after a complete scored run."""

    config_file = Path(config_path).resolve()
    config = _load_config(config_file)
    config_base = config_file.parent
    paegen_root = _resolve(config_base, config["repositories"]["paegen"])
    verclo_root = _resolve(config_base, config["repositories"]["verclo"])
    paeforge_root = Path(__file__).resolve().parents[2]
    selected_output = Path(output_root).resolve() if output_root else _resolve(config_base, config["output"]["root"])
    _ensure_external_output(selected_output, (paegen_root, verclo_root, paeforge_root))
    identifier = _safe_run_id(run_id or _default_run_id(config))
    run_root = selected_output / config["output"]["contract_series"] / identifier
    run_root.mkdir(parents=True, exist_ok=False)
    log = StructuredRunLog(run_root / "logs" / "events.jsonl", identifier)
    manifest_path = run_root / "run-manifest.json"
    result_path = run_root / "verclo-output" / "verclo-result.json"
    evaluation_path = run_root / "evaluation" / "evaluation-report.json"
    metrics_path = run_root / "metrics" / "summary.json"
    started_at = utc_now()
    config_digest = sha256_digest(config)
    log.emit("pipeline", "run_started", "STARTED", config_sha256=config_digest)
    try:
        for name, root in (("PaEGen", paegen_root), ("VERCLO", verclo_root), ("PaEForge", paeforge_root)):
            if not (root / "src").is_dir():
                raise FileNotFoundError(f"{name} source directory not found: {root / 'src'}")
        write_json(run_root / "configuration" / "requested-config.json", config)
        identities = {
            "schema_version": "1.0.0",
            "captured_at": utc_now(),
            "runtime": runtime_identity(),
            "components": {
                "paegen": source_identity("PaEGen", paegen_root),
                "verclo": source_identity("VERCLO", verclo_root),
                "paeforge": source_identity("PaEForge", paeforge_root),
            },
        }
        write_json(run_root / "configuration" / "source-identities.json", identities)
        paegen_revision = identities["components"]["paegen"]["source_revision"]
        verclo_revision = identities["components"]["verclo"]["source_revision"]
        log.emit("capture", "configuration_and_sources_captured", "COMPLETED")

        sys.path.insert(0, str(paegen_root / "src"))
        sys.path.insert(0, str(verclo_root / "src"))
        from htgl_dataset_generator.paegen import (  # type: ignore[import-not-found]
            compile_adversarial_campaign,
            compile_smart_grid_benchmark,
            load_adversarial_controls,
            load_smart_grid_scenarios,
            validate_adversarial_campaign,
            validate_paegen_build,
        )
        from verclo import PolicyRegistry  # type: ignore[import-not-found]

        scenario_directory_value = config["paegen"].get("scenario_directory")
        if scenario_directory_value:
            scenario_directory = _resolve(config_base, scenario_directory_value)
            definitions = load_smart_grid_scenarios(
                scenario_directory, require_canonical_catalog=False
            )
        else:
            scenario_directory = None
            definitions = load_smart_grid_scenarios()
        definition = next(
            (row for row in definitions if row.scenario_id == config["paegen"]["scenario_id"]),
            None,
        )
        if definition is None:
            raise ValueError(f"unknown PaEGen scenario: {config['paegen']['scenario_id']}")
        log.emit(
            "paegen", "generation_started", "STARTED",
            scenario_id=definition.scenario_id,
            scenario_directory=None if scenario_directory is None else str(scenario_directory),
        )
        selected_variant = str(config["paegen"]["variant_id"])
        if selected_variant.startswith("ADV-"):
            controls = load_adversarial_controls()
            adversarial = compile_adversarial_campaign(
                controls, root_seed=config["paegen"]["root_seed"]
            )
            validate_adversarial_campaign(adversarial, controls)
            fixture_id = "ADV-REPLAY" if selected_variant == "ADV-REPLAY-MISBOUND" else selected_variant
            fixture = next(
                (row for row in adversarial.fixtures if row.fixture_id == fixture_id),
                None,
            )
            if fixture is None:
                raise ValueError(f"unknown PaEGen adversarial fixture: {selected_variant}")
            if fixture.scenario_id != definition.scenario_id:
                raise ValueError(
                    f"adversarial fixture {selected_variant} belongs to {fixture.scenario_id}, "
                    f"not {definition.scenario_id}"
                )
            truth_payload = fixture.attacked_ground_truth.payload
            observer_views = dict(fixture.observer_views)
            if selected_variant == "ADV-REPLAY-MISBOUND":
                amended_views = {}
                for profile_id, artifact in observer_views.items():
                    payload = json.loads(json.dumps(artifact.payload))
                    case = next(
                        row for row in payload["records"]
                        if row.get("record_type") == "case_declaration"
                    )
                    evidence = case["submitted_evidence"]
                    if len(evidence) >= 3 and evidence[-1]["receipt_id"] == evidence[-2]["receipt_id"]:
                        evidence[-1]["obligation_id"] = evidence[0]["obligation_id"]
                    amended_views[profile_id] = SimpleNamespace(
                        payload=payload,
                        sha256=sha256_digest(payload),
                    )
                observer_views = amended_views
            replica = SimpleNamespace(
                replicate_id=int(truth_payload["replicate_id"]),
                ground_truth=fixture.attacked_ground_truth,
                observer_views=observer_views,
                scenario_manifest=SimpleNamespace(payload={
                    "schema_version": "1.0.0",
                    "run_id": truth_payload["run_id"],
                    "scenario_id": truth_payload["scenario_id"],
                    "replicate_id": truth_payload["replicate_id"],
                    "seed_stream_digest": truth_payload["seed_stream_digest"],
                    "adversarial_fixture_id": fixture.fixture_id,
                    "attack_type": fixture.attack_type,
                    "control_digest": adversarial.control_digest,
                }),
            )
            build = SimpleNamespace(run_id=truth_payload["run_id"])
        else:
            build = compile_smart_grid_benchmark(
                [definition], root_seed=config["paegen"]["root_seed"]
            )
            validate_paegen_build(build)
            replica = _select_paegen_replica(build, selected_variant)
        observer_profile_id = config["paegen"]["observer_profile_id"]
        if observer_profile_id not in replica.observer_views:
            raise ValueError(f"PaEGen observer profile not found: {observer_profile_id}")
        write_json(
            run_root / "generation" / "public" / "paegen-scenario-manifest.json",
            replica.scenario_manifest.payload,
        )
        write_json(
            run_root / "generation" / "public" / "paegen-observer-bundle.json",
            replica.observer_views[observer_profile_id].payload,
        )
        log.emit(
            "paegen", "generation_completed", "COMPLETED",
            paegen_run_id=build.run_id,
            replicate_id=replica.replicate_id,
            seed_stream_digest=replica.scenario_manifest.payload["seed_stream_digest"],
        )

        policy_payload = translated_policy(definition.payload)
        policy_directory = run_root / "configuration" / "policies"
        policy_path = policy_directory / "translated-policy.json"
        write_json(policy_path, policy_payload)
        policy_registry = PolicyRegistry.load(policy_directory)
        policy = policy_registry.get(policy_payload["profile_id"])
        policy_ref = {
            "profile_id": policy.profile_id,
            "version": policy.version,
            "sha256": policy.sha256,
            "minimum_evidence_grade": policy.default_rule.minimum_evidence_grade,
        }
        case_record = next(
            row for row in replica.observer_views[observer_profile_id].payload["records"]
            if row["record_type"] == "case_declaration"
        )
        projection = build_projection(
            scenario=definition.payload,
            paegen_replica=replica,
            observer_profile_id=observer_profile_id,
            projection_config=config["projection"],
            policy_ref=policy_ref,
            root_seed=config["paegen"]["root_seed"],
            paegen_source_revision=paegen_revision,
            generated_at=case_record["accepted_at"],
        )
        verifier_directory = run_root / "verifier-input"
        write_verifier_bundle(
            verifier_directory,
            projection.manifest,
            projection.observer_projection,
            projection.receipt_stream,
        )
        log.emit(
            "projection", "verifier_bundle_frozen", "COMPLETED",
            case_id=projection.manifest["case_id"],
            exchange_id=projection.manifest["exchange_id"],
            input_directory=str(verifier_directory.relative_to(run_root)),
            security_diagnostics=list(projection.security_diagnostics),
        )

        if (run_root / "oracle").exists():
            raise RuntimeError("oracle directory must not exist before VERCLO execution")
        result_path.parent.mkdir(parents=True, exist_ok=True)
        worker_environment = os.environ.copy()
        worker_environment["PYTHONPATH"] = os.pathsep.join(
            (str(paeforge_root / "src"), str(verclo_root / "src"))
        )
        worker_command = [
            sys.executable,
            "-m",
            "paeforge_pipeline.verclo_worker",
            "--input",
            str(verifier_directory),
            "--policy-directory",
            str(policy_directory),
            "--output",
            str(result_path),
            "--source-revision",
            verclo_revision,
            "--configuration-sha256",
            sha256_digest(config["verclo"]),
        ]
        log.emit("verclo", "worker_started", "STARTED", oracle_materialized=False)
        with tempfile.TemporaryDirectory(prefix="paeforge-verclo-") as worker_directory:
            completed = subprocess.run(
                worker_command,
                cwd=worker_directory,
                env=worker_environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        verclo_result = read_json(result_path)
        read_verifier_bundle(verifier_directory)
        log.emit(
            "verclo", "result_frozen", "COMPLETED",
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            result_sha256=sha256_digest(verclo_result),
            oracle_materialized=False,
        )

        oracle_root = run_root / "oracle"
        truth_path = oracle_root / "sealed-ground-truth.json"
        mapping_path = oracle_root / "obligation-id-map.json"
        write_json(truth_path, replica.ground_truth.payload)
        mapping_payload = {
            "schema_version": "1.0.0",
            "access_class": "evaluator_only",
            "case_id": projection.manifest["case_id"],
            "mapping": {key: list(value) for key, value in projection.obligation_id_map.items()},
            "visibility": projection.obligation_visibility,
        }
        write_json(mapping_path, mapping_payload)
        log.emit("oracle", "sealed_truth_opened_after_result_freeze", "COMPLETED")

        evaluation = build_evaluation_report(
            sealed_truth=replica.ground_truth.payload,
            verclo_result=verclo_result,
            evaluated_at=utc_now(),
            visibility_attribution=config["evaluation"]["visibility_attribution"],
            provenance={
                "producer": "PaEBench",
                "producer_version": "1.0.0",
                "source_revision": paegen_revision,
                "generated_at": utc_now(),
                "verclo_result_frozen_before_truth_open": True,
            },
            obligation_id_map=projection.obligation_id_map,
        )
        write_json(evaluation_path, evaluation)
        metrics = {
            "schema_version": "1.0.0",
            "pipeline_version": PIPELINE_VERSION,
            "run_id": identifier,
            "case_id": projection.manifest["case_id"],
            "expected_closure": evaluation["expected_closure"],
            "observed_closure": evaluation["observed_closure"],
            "classification": evaluation["classification"],
            "false_closure": evaluation["metrics"]["false_closure"],
            "missed_closure": evaluation["metrics"]["missed_closure"],
            "obligation_metrics": {
                key: evaluation["metrics"][key]
                for key in (
                    "truth_obligation_count",
                    "verclo_obligation_count",
                    "true_positive_obligations",
                    "false_positive_obligations",
                    "false_negative_obligations",
                )
            },
            "executed_operations_q": verclo_result["execution"]["executed_operations_q"],
            "verifier_input_bytes": sum(
                path.stat().st_size for path in verifier_directory.iterdir() if path.is_file()
            ),
            "verclo_result_bytes": result_path.stat().st_size,
        }
        write_json(metrics_path, metrics)
        log.emit("evaluation", "comparison_completed", "COMPLETED", classification=evaluation["classification"])
        finished_at = utc_now()
        log.emit("pipeline", "run_completed", "COMPLETED", manifest="run-manifest.json")
        inventory = artifact_inventory(run_root, excluded=(manifest_path,))
        run_manifest = {
            "schema_id": "https://paeforge.local/schema/run-manifest/v1",
            "schema_version": "1.0.0",
            "pipeline_version": PIPELINE_VERSION,
            "contract_version": "1.0.0",
            "model_version": "PAE-FECM-v1.0.0",
            "run_id": identifier,
            "status": "COMPLETED",
            "started_at": started_at,
            "finished_at": finished_at,
            "configuration": {
                "path": "configuration/requested-config.json",
                "sha256": config_digest,
                "source_path": str(config_file),
            },
            "sources": {
                key: {
                    "git_head": value["git_head"],
                    "tree_sha256": value["tree_sha256"],
                    "source_revision": value["source_revision"],
                }
                for key, value in identities["components"].items()
            },
            "seed": projection.manifest["seed"],
            "selection": {
                "scenario_id": config["paegen"]["scenario_id"],
                "variant_id": config["paegen"]["variant_id"],
                "observer_profile_id": observer_profile_id,
                "case_id": projection.manifest["case_id"],
                "exchange_id": projection.manifest["exchange_id"],
            },
            "stage_order": ["capture", "paegen", "projection", "verclo", "oracle", "evaluation"],
            "oracle_isolation": {
                "verclo_subprocess": True,
                "paegen_source_on_worker_pythonpath": False,
                "truth_materialized_after_result_freeze": True,
            },
            "results": {
                "verclo_result": "verclo-output/verclo-result.json",
                "evaluation_report": "evaluation/evaluation-report.json",
                "metrics": "metrics/summary.json",
                "structured_log": "logs/events.jsonl",
                "classification": evaluation["classification"],
            },
            "reproduction": {
                "entry_point": "PaEForge/run.py",
                "command_template": f"python3 PaEForge/run.py --config {config_file} --run-id <new-run-id>",
                "output_series": config["output"]["contract_series"],
            },
            "artifact_inventory": inventory,
        }
        validate_document(run_manifest)
        write_json(manifest_path, run_manifest)
        return PipelineResult(identifier, run_root, manifest_path, result_path, evaluation_path, metrics_path)
    except BaseException as error:
        log.emit(
            "pipeline", "run_failed", "FAILED",
            error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc(),
        )
        failure_manifest = {
            "schema_id": "https://paeforge.local/schema/run-manifest/v1",
            "schema_version": "1.0.0",
            "pipeline_version": PIPELINE_VERSION,
            "run_id": identifier,
            "status": "FAILED",
            "started_at": started_at,
            "finished_at": utc_now(),
            "configuration_sha256": config_digest,
            "error": {"type": type(error).__name__, "message": str(error)},
            "structured_log": "logs/events.jsonl",
        }
        if not manifest_path.exists():
            validate_document(failure_manifest)
            write_json(manifest_path, failure_manifest)
        raise
