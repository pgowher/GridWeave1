"""Deterministic PaEBench v1.0 reference build and verification."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from htgl_dataset_generator.artifacts.canonical import atomic_write_bytes, canonical_json_bytes, sha256_hex

from .adversarial import (
    compile_adversarial_campaign,
    export_adversarial_campaign,
    load_adversarial_controls,
    validate_adversarial_campaign,
)
from .export import export_paegen
from .smart_grid import compile_smart_grid_benchmark, load_smart_grid_scenarios
from .validation import FORBIDDEN_OBSERVER_KEYS, validate_paegen_build


RELEASE_ID = "PaEBench-v1.0.0"
CANONICAL_SEED = "PAEBENCH-SMART-GRID-v1"
ADVERSARIAL_SEED = "PAEBENCH-ADVERSARIAL-v1"
REFERENCE_HASH_FILE = "reference-hashes.json"


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_json_bytes(payload)
    if path.exists() and path.read_bytes() != encoded:
        raise FileExistsError(f"refusing to replace non-identical release artifact: {path}")
    atomic_write_bytes(path, encoded)


def _hash_tree(root: Path, *, excluded: Iterable[str] = ()) -> list[dict[str, str]]:
    exclusions = frozenset(excluded)
    return [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_hex(path.read_bytes())}
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.relative_to(root).as_posix() not in exclusions
    ]


def _walk_keys(value: Any):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def _outcomes(payloads: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(
        str(payload["cases"][0]["closure_ground_truth"]["outcome"])
        for payload in payloads
    )
    return dict(sorted(counts.items()))


def build_reference(output_root: str | Path) -> Mapping[str, Any]:
    """Materialise the deterministic reference corpus in a new or identical directory."""

    root = Path(output_root).resolve()
    canonical = compile_smart_grid_benchmark(root_seed=CANONICAL_SEED)
    validate_paegen_build(canonical)
    controls = load_adversarial_controls()
    adversarial = compile_adversarial_campaign(controls, root_seed=ADVERSARIAL_SEED)
    validate_adversarial_campaign(adversarial, controls)
    canonical_export = export_paegen(canonical, root / "canonical")
    adversarial_export = export_adversarial_campaign(adversarial, root / "adversarial")

    observer_files = tuple(sorted((root / "canonical" / "observer-input").rglob("*.json"))) + tuple(
        sorted((root / "adversarial" / "observer-input").rglob("*.json"))
    )
    forbidden = FORBIDDEN_OBSERVER_KEYS | controls.forbidden_fields | controls.hidden_topology_fields
    leakage_findings: list[dict[str, Any]] = []
    for path in observer_files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        collisions = sorted(set(_walk_keys(payload)) & forbidden)
        if collisions:
            leakage_findings.append({
                "path": path.relative_to(root).as_posix(),
                "forbidden_keys": collisions,
            })
    audit = {
        "release_id": RELEASE_ID,
        "audit": "observer_projection_oracle_leakage",
        "observer_files_scanned": len(observer_files),
        "forbidden_key_count": len(forbidden),
        "finding_count": len(leakage_findings),
        "findings": leakage_findings,
        "result": "PASS" if not leakage_findings else "FAIL",
    }
    _write_json(root / "leakage-audit.json", audit)
    if leakage_findings:
        raise ValueError("observer projection leakage audit failed")

    canonical_payloads = [item.ground_truth.payload for item in canonical.replicas]
    attacked_payloads = [item.attacked_ground_truth.payload for item in adversarial.fixtures]
    represented_subjects = {
        str(definition.payload["synthetic_data_profile"]["subject_namespace"])
        for definition in load_smart_grid_scenarios()
    }
    summary = {
        "release_id": RELEASE_ID,
        "model_version": canonical.model_version,
        "scale_accounting": {
            "N_represented_population": len(represented_subjects),
            "N_unit": "synthetic lifecycle subject namespaces",
            "n_materialized_records": len(canonical.replicas) + len(adversarial.fixtures),
            "n_unit": "experimental erasure-case instances",
            "n_components": {"canonical_cases": len(canonical.replicas), "attacked_cases": len(adversarial.fixtures)},
            "q_executed_governance_operations": None,
            "q_status": "NOT_EXECUTED",
            "q_explanation": "PaEBench generates cases; C-PaE/VERCLO protocol execution is outside this release gate.",
        },
        "reference_statistics": {
            "canonical_scenarios": len({item.scenario_id for item in canonical.replicas}),
            "canonical_case_outcomes": _outcomes(canonical_payloads),
            "adversarial_attack_fixtures": len(adversarial.fixtures),
            "attacked_case_outcomes": _outcomes(attacked_payloads),
            "paired_clean_attack_baselines": len(adversarial.fixtures),
            "canonical_observer_projections": sum(len(item.observer_views) for item in canonical.replicas),
            "restricted_adversarial_projections": sum(len(item.observer_views) for item in adversarial.fixtures),
            "known_indistinguishability_cases": sum(
                item.indistinguishability_class is not None for item in adversarial.fixtures
            ),
            "canonical_export_files": canonical_export.file_count,
            "adversarial_export_files": adversarial_export.file_count,
        },
        "seeds": {"canonical": CANONICAL_SEED, "adversarial": ADVERSARIAL_SEED},
        "digests": {
            "canonical_export": canonical_export.export_digest,
            "adversarial_export": adversarial_export.export_digest,
            "adversarial_controls": adversarial.control_digest,
        },
        "oracle_leakage_audit": audit["result"],
        "proof_limit": "Synthetic benchmark truth and evidence grades do not establish physical destruction.",
    }
    _write_json(root / "summary.json", summary)
    hashes = {
        "release_id": RELEASE_ID,
        "algorithm": "SHA-256",
        "files": _hash_tree(root, excluded=(REFERENCE_HASH_FILE,)),
    }
    _write_json(root / REFERENCE_HASH_FILE, hashes)
    return summary


def verify_reference(reference_root: str | Path) -> Mapping[str, Any]:
    """Verify every reference payload against the frozen SHA-256 inventory."""

    root = Path(reference_root).resolve()
    manifest = json.loads((root / REFERENCE_HASH_FILE).read_text(encoding="utf-8"))
    actual = _hash_tree(root, excluded=(REFERENCE_HASH_FILE,))
    if actual != manifest["files"]:
        raise ValueError("reference hash inventory mismatch")
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    audit = json.loads((root / "leakage-audit.json").read_text(encoding="utf-8"))
    if audit["result"] != "PASS" or audit["finding_count"] != 0:
        raise ValueError("observer leakage gate is not satisfied")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or verify PaEBench v1.0 reference outputs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("output")
    verify = subparsers.add_parser("verify")
    verify.add_argument("reference")
    args = parser.parse_args(argv)
    result = build_reference(args.output) if args.command == "build" else verify_reference(args.reference)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
