"""Deterministic, sealed PaEBench case extension; frozen v1.0 is read only."""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from .benchmark_contract import load_benchmark_study_contract
from .extension_v1_2_oracle import LABELS, canonical, digest, evaluate, graph_material


ROOT = Path(__file__).resolve().parents[3]
PLAN = ROOT / "configs/pae_bench/v1_2/study_plan_v1_2.json"
PROFILE = ROOT / "configs/pae_bench/v1_2/core_families.json"
RELEASE = ROOT / "releases/PaEBench-v1.2-extension"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
FORBIDDEN_KEYS = {"closure_ground_truth", "verification_status_truth", "variant_class",
                  "attack_id", "expected_detection", "hidden_topology", "expected_closure",
                  "source_family_id", "source_variant_id", "source_profile"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def stamp(instant: datetime) -> str:
    return instant.isoformat().replace("+00:00", "Z")


def opaque(seed: str, family: str, kind: str, value: str) -> str:
    return kind.lower() + "-" + sha256(canonical([seed, family, kind, value])).hexdigest()[:16]


def _unique(rows: list[dict], field: str) -> set[str]:
    ids = [row[field] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate {field}")
    return set(ids)


def validate_family(family: dict, schema: dict) -> None:
    Draft202012Validator(schema).validate(family)
    repositories = _unique(family["repositories"], "repository_id")
    assets = _unique(family["assets"], "asset_id")
    obligations = _unique(family["obligations"], "obligation_id")
    _unique(family["variants"], "variant_id")
    parents = {}
    for asset in family["assets"]:
        if asset["repository_id"] not in repositories:
            raise ValueError("unknown asset repository")
        if set(asset["parent_asset_ids"]) - assets:
            raise ValueError("unknown parent asset")
        parents[asset["asset_id"]] = asset["parent_asset_ids"]
    visiting, visited = set(), set()

    def walk(asset_id: str) -> None:
        if asset_id in visiting:
            raise ValueError("asset lineage cycle")
        if asset_id in visited:
            return
        visiting.add(asset_id)
        for parent in parents[asset_id]:
            walk(parent)
        visiting.remove(asset_id)
        visited.add(asset_id)

    for asset_id in assets:
        walk(asset_id)
    if {row["asset_id"] for row in family["obligations"]} != assets:
        raise ValueError("assets must have exactly one declared obligation")
    for row in family["variants"]:
        if row.get("target_obligation_id") and row["target_obligation_id"] not in obligations:
            raise ValueError("unknown variant target")
        if row["operation"] in {"OMIT_ONE", "CONFLICT", "EARLY_OMIT", "INVALID_SIGNATURE",
                                "MATERIAL_MISSING", "LATE_ONE"} and not row.get("target_obligation_id"):
            raise ValueError("target required for operation")


def transfer_families(plan: dict) -> list[dict]:
    results = []
    for source in plan["independent_use_cases"]:
        assets = source["assets"]
        asset_map = {row["asset_id"]: row for row in assets}
        obligations = []
        for index, obligation in enumerate(source["obligations"]):
            for asset_id in obligation["asset_ids"]:
                obligations.append({
                    "obligation_id": obligation["obligation_id"], "asset_id": asset_id,
                    "principal_id": obligation["responsible_actor_id"],
                    "required_disposition": obligation["required_disposition"],
                    "evidence_floor": obligation["evidence_floor"],
                    "deadline_hours": 48 + index * 24,
                })
        variants = []
        for item in source["variants"]:
            perturbation = item["perturbation"]
            operation = "CONFLICT" if item["expected_closure"] == "DISPUTED" else (
                "OMIT_ONE" if item["expected_closure"] == "PARTIALLY_CLOSED" else "NONE")
            # The v1 contract describes intended mechanism-supported transfer
            # success. This wire format carries only an unsigned Boolean.
            # Retain E4 floors; a NONE variant remains incomplete without proof.
            expected = item["expected_closure"]
            if expected in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"} and any(o["evidence_floor"] == "E4" and o["required_disposition"] != "RETAINED" for o in obligations):
                expected = "PARTIALLY_CLOSED"
            target = next((row["obligation_id"] for row in obligations
                           if row["obligation_id"] in perturbation), None)
            if target is None and operation != "NONE":
                target = next((row["obligation_id"] for row in obligations
                               if row["obligation_id"].split("-")[-1].lower() in perturbation.lower()), None)
            if operation != "NONE" and target is None:
                raise ValueError(f"transfer perturbation has no obligation: {perturbation}")
            variants.append({"variant_id": item["variant_id"], "operation": operation,
                             "expected_closure": expected,
                             **({"target_obligation_id": target} if target else {})})
        results.append({"family_id": source["use_case_id"], "domain": source["domain"],
                        "subject_namespace": "SYN-" + source["use_case_id"], "split": "test",
                        "repositories": [{"repository_id": r["repository_id"], "kind": r["kind"],
                                          "observer_visible": r["observer_visible"]}
                                         for r in source["repositories"]],
                        "assets": [{"asset_id": a["asset_id"], "repository_id": a["repository_id"],
                                    "parent_asset_ids": a["parent_asset_ids"]} for a in assets],
                        "obligations": obligations, "variants": variants})
        if len(asset_map) != len(obligations):
            raise ValueError("transfer requires one obligation per asset")
    return results


def build_case(family: dict, variant: dict, seed: str) -> tuple[dict, dict]:
    fid = family["family_id"]
    ident = lambda kind, value: opaque(seed, fid, kind, value)
    case_id = ident("case", fid)
    unit_id = ident("unit", variant["variant_id"])
    repo_map = {r["repository_id"]: ident("repository", r["repository_id"])
                for r in family["repositories"]}
    asset_map = {a["asset_id"]: ident("asset", a["asset_id"]) for a in family["assets"]}
    obligation_map = {o["obligation_id"]: ident("obligation", o["obligation_id"])
                      for o in family["obligations"]}
    repositories = sorted([{"repository_id": repo_map[r["repository_id"]],
                            "kind": r["kind"], "observer_visible": r["observer_visible"]}
                           for r in family["repositories"]], key=lambda r: r["repository_id"])
    assets = sorted([{"asset_id": asset_map[a["asset_id"]],
                      "repository_id": repo_map[a["repository_id"]],
                      "parent_asset_ids": sorted(asset_map[x] for x in a["parent_asset_ids"])}
                     for a in family["assets"]], key=lambda a: a["asset_id"])
    asset_source = {a["asset_id"]: a for a in family["assets"]}
    obligations = []
    for source in family["obligations"]:
        disposition = source["required_disposition"]
        obligations.append({"obligation_id": obligation_map[source["obligation_id"]],
                            "asset_id": asset_map[source["asset_id"]],
                            "replica_id": ident("replica", source["asset_id"]),
                            "repository_id": repo_map[asset_source[source["asset_id"]]["repository_id"]],
                            "principal_id": ident("principal", source["principal_id"]),
                            "permitted_dispositions": [disposition],
                            "evidence_floor": source["evidence_floor"],
                            "deadline": stamp(START + timedelta(hours=source["deadline_hours"]))})
        if variant["operation"] == "FLOOR_RAISE" and source["obligation_id"] == variant.get("target_obligation_id"):
            obligations[-1]["evidence_floor"] = "E4"
    obligations.sort(key=lambda o: o["obligation_id"])
    max_deadline = max(o["deadline_hours"] for o in family["obligations"])
    evaluation_time = START + timedelta(hours=max_deadline + 24)
    if variant["operation"] == "EARLY_OMIT":
        evaluation_time = START + timedelta(hours=12)
    authorities = [ident("authority", "exception-authority")]
    def private_key(principal: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            sha256(canonical([seed, fid, "signing-key", principal])).digest())

    def public_key(principal: str) -> str:
        return private_key(principal).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()

    policy = {"exception_authority_ids": authorities,
              "exception_authority_public_keys": {authorities[0]: public_key("exception-authority")},
              "principal_public_keys": {
                  ident("principal", source["principal_id"]): public_key(source["principal_id"])
                  for source in family["obligations"]}}
    exceptions = []
    receipts = []
    source_dispositions = []
    target = variant.get("target_obligation_id")
    for source in family["obligations"]:
        oid = source["obligation_id"]
        public_oid = obligation_map[oid]
        disposition = source["required_disposition"]
        if variant["operation"] in {"EXCEPTION_TARGET", "INVALID_EXCEPTION"} and oid == target:
            signed_exception = {"obligation_id": public_oid, "authority_id": authorities[0],
                                "basis_commitment": digest([seed, fid, oid, "retention-basis"]),
                                "effective_at": stamp(START), "expires_at": stamp(START + timedelta(days=365))}
            signature = private_key("exception-authority").sign(canonical(signed_exception)).hex()
            if variant["operation"] == "INVALID_EXCEPTION":
                signature = "00" * 64
            exceptions.append({**signed_exception, "public_key": public_key("exception-authority"), "signature": signature})
            source_dispositions.append({"obligation_id": oid, "disposition": "EXCEPTED" if variant["operation"] == "EXCEPTION_TARGET" else "INVALID_EXCEPTION"})
            continue
        if disposition == "RETAINED":
            signed_exception = {"obligation_id": public_oid, "authority_id": authorities[0],
                                "basis_commitment": digest([seed, fid, oid, "retention-basis"]),
                                "effective_at": stamp(START),
                                "expires_at": stamp(START + timedelta(days=365))}
            exceptions.append({**signed_exception, "public_key": public_key("exception-authority"),
                               "signature": private_key("exception-authority").sign(
                                   canonical(signed_exception)).hex()})
            source_dispositions.append({"obligation_id": oid, "disposition": "EXCEPTED"})
            continue
        omit = variant["operation"] == "OMIT_ALL" or (
            variant["operation"] in {"OMIT_ONE", "EARLY_OMIT"} and oid == target)
        if omit:
            source_dispositions.append({"obligation_id": oid, "disposition": "UNRESOLVED"})
            continue
        private = private_key(source["principal_id"])
        signer_public_key = public_key(source["principal_id"])
        event_time = START + timedelta(hours=1)
        if variant["operation"] == "LATE_ONE" and oid == target:
            event_time = START + timedelta(hours=source["deadline_hours"] + 1)
        if variant["operation"] == "FUTURE_ONE" and oid == target:
            event_time = evaluation_time + timedelta(hours=1)
        signed = {"receipt_id": ident("receipt", oid), "obligation_id": public_oid,
                  "issuer_id": ident("principal", source["principal_id"]),
                  "claimed_disposition": disposition, "event_time": stamp(event_time)}
        receipt = {**signed, "public_key": signer_public_key, "signature": private.sign(canonical(signed)).hex(),
                   "anchor_commitment": digest(signed),
                   "mechanism_attestation": source["evidence_floor"] == "E4"}
        if variant["operation"] == "INVALID_SIGNATURE" and oid == target:
            receipt["signature"] = "00" * 64
        if variant["operation"] == "MATERIAL_MISSING" and oid == target:
            receipt["public_key"] = None
        if variant["operation"] == "KEY_UNKNOWN" and oid == target:
            policy["principal_public_keys"].pop(signed["issuer_id"], None)
        if variant["operation"] == "ANCHOR_MISSING" and oid == target:
            receipt["anchor_commitment"] = ""
        receipts.append(receipt)
        source_dispositions.append({"obligation_id": oid, "disposition": disposition})
        if variant["operation"] == "CONFLICT" and oid == target:
            conflict_signed = {**signed, "receipt_id": ident("receipt-conflict", oid),
                               "claimed_disposition": "FAILED"}
            receipts.append({**conflict_signed, "public_key": signer_public_key,
                             "signature": private.sign(canonical(conflict_signed)).hex(),
                             "anchor_commitment": digest(conflict_signed),
                             "mechanism_attestation": source["evidence_floor"] == "E4"})
            source_dispositions[-1]["disposition"] = "CONTRADICTORY"
    case = {"schema_version": "1.2.0", "case_id": case_id,
            "evaluation_time": stamp(evaluation_time), "assets": assets,
            "repositories": repositories, "obligations": obligations,
            "receipts": sorted(receipts, key=lambda r: r["receipt_id"]),
            "exceptions": sorted(exceptions, key=lambda e: e["obligation_id"]), "policy": policy}
    case["scope_commitment"] = digest(graph_material(case))
    if variant["operation"] == "BASELINE_MISSING":
        case["scope_commitment"] = None
    if variant["operation"] == "BASELINE_INVALID":
        case["scope_commitment"] = "0" * 64
    truth = evaluate(case)
    if truth["outcome"] != variant["expected_closure"]:
        raise ValueError(f"declared label disagrees with generated facts: {fid}/{variant['variant_id']}: "
                         f"{variant['expected_closure']} != {truth['outcome']}")
    sealed = {"unit_id": unit_id, "case_id": case_id, "source_family_id": fid,
              "source_variant_id": variant["variant_id"], "domain": family["domain"],
              "subject_namespace": family["subject_namespace"], "split": family["split"],
              "source_profile_sha256": digest(family), "source_dispositions": source_dispositions,
              "hidden_world_copy": variant["operation"] == "HIDDEN_COPY",
              "closure_ground_truth": truth, "observer_sha256": sha256(canonical(case)).hexdigest()}
    return case, sealed


def audit_projection(observer: dict, sealed: dict, relative_path: str) -> list[str]:
    findings = []
    def check(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in FORBIDDEN_KEYS or "truth" in key.lower() or "attack" in key.lower():
                    findings.append("FORBIDDEN_KEY:" + key)
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)
    check(observer)
    public_bytes = canonical(observer).decode()
    for secret in (sealed["source_family_id"], sealed["source_variant_id"],
                   sealed["subject_namespace"], sealed["closure_ground_truth"]["outcome"]):
        if secret in public_bytes or secret in relative_path:
            findings.append("SEALED_VALUE_EXPOSED:" + secret)
    if any(marker in relative_path.lower() for marker in ("closed", "partial", "disputed", "open", "attack")):
        findings.append("LABEL_IN_PATH")
    return sorted(set(findings))


def negative_controls(observer: dict, sealed: dict) -> dict[str, bool]:
    key_canary = deepcopy(observer)
    key_canary["closure_ground_truth"] = "CANARY"
    value_canary = deepcopy(observer)
    value_canary["canary"] = sealed["subject_namespace"]
    return {"forbidden_key_rejected": bool(audit_projection(key_canary, sealed, "observer.json")),
            "secret_value_rejected": bool(audit_projection(value_canary, sealed, "observer.json")),
            "label_path_rejected": bool(audit_projection(observer, sealed, "closed/observer.json"))}


def load_plan() -> tuple[dict, list[dict], dict]:
    plan = read_json(PLAN)
    schema = read_json(ROOT / "schemas/paebench-study-plan-v1_2.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(plan)
    original = load_benchmark_study_contract()
    if plan["source_contract_sha256"] != original.sha256:
        raise ValueError("source contract digest changed")
    for key, value in original.payload.items():
        if key not in {"schema_version", "benchmark_id", "status"} and plan[key] != value:
            raise ValueError(f"v1 study contract field changed: {key}")
    families = read_json(PROFILE) + transfer_families(plan)
    family_schema = read_json(ROOT / plan["extension"]["profile_schema"])
    for family in families:
        validate_family(family, family_schema)
    if len({f["family_id"] for f in families}) != len(families):
        raise ValueError("duplicate family identifiers")
    return plan, families, family_schema


def materialize(seed: str | None = None) -> dict[str, Any]:
    plan, families, _ = load_plan()
    seed = seed or plan["extension"]["seed"]
    plan["extension"]["seed"] = seed
    observer_schema = read_json(ROOT / "schemas/paebench-observer-case-v1_2.schema.json")
    sealed_schema = read_json(ROOT / "schemas/paebench-sealed-case-v1_2.schema.json")
    Draft202012Validator.check_schema(observer_schema)
    Draft202012Validator.check_schema(sealed_schema)
    units = []
    leakage = []
    for family in families:
        for variant in family["variants"]:
            observer, sealed = build_case(family, variant, seed)
            Draft202012Validator(observer_schema).validate(observer)
            Draft202012Validator(sealed_schema).validate(sealed)
            path = "observer-inputs/" + sealed["unit_id"] + ".json"
            leakage.extend({"unit_id": sealed["unit_id"], "finding": finding}
                           for finding in audit_projection(observer, sealed, path))
            units.append({"observer": observer, "sealed": sealed, "path": path})
    if leakage:
        raise ValueError("projection leakage: " + str(leakage))
    canaries = negative_controls(units[0]["observer"], units[0]["sealed"])
    if not all(canaries.values()):
        raise ValueError("projection audit negative control failed")
    splits = defaultdict(list)
    class_support = defaultdict(Counter)
    operation_support = defaultdict(Counter)
    projection_hashes = defaultdict(list)
    for unit in units:
        sealed = unit["sealed"]
        splits[sealed["split"]].append(sealed["unit_id"])
        class_support[sealed["split"]][sealed["closure_ground_truth"]["outcome"]] += 1
        projection_hashes[sealed["observer_sha256"]].append(sealed)
        family = next(f for f in families if f["family_id"] == sealed["source_family_id"])
        variant = next(v for v in family["variants"] if v["variant_id"] == sealed["source_variant_id"])
        operation_support[sealed["split"]][variant["operation"]] += 1
    for group in projection_hashes.values():
        if len({s["split"] for s in group}) > 1:
            raise ValueError("equivalent observer cases span splits")
    def shingles(observer: dict) -> set[str]:
        return ({"repo:" + r["kind"] for r in observer["repositories"]}
                | {"obligation:" + o["permitted_dispositions"][0] + ":" + o["evidence_floor"]
                   for o in observer["obligations"]}
                | {"receipt:" + r["claimed_disposition"] for r in observer["receipts"]}
                | {"exception:" + str(bool(observer["exceptions"]))})

    near = []
    across_split_near = []
    for i, left in enumerate(units):
        for right in units[i + 1:]:
            if left["sealed"]["observer_sha256"] == right["sealed"]["observer_sha256"]:
                continue
            a, b = shingles(left["observer"]), shingles(right["observer"])
            if len(a & b) / len(a | b) >= 0.9:
                pair = sorted([left["sealed"]["unit_id"], right["sealed"]["unit_id"]])
                near.append(pair)
                if left["sealed"]["split"] != right["sealed"]["split"]:
                    across_split_near.append(pair)
    records = [{"unit_id": u["sealed"]["unit_id"], "case_id": u["sealed"]["case_id"],
                "family_id": u["sealed"]["source_family_id"], "split": u["sealed"]["split"],
                "class": u["sealed"]["closure_ground_truth"]["outcome"],
                "observer_sha256": u["sealed"]["observer_sha256"]} for u in units]
    return {"plan": plan, "families": families, "units": units, "records": records,
            "split_manifest": {"policy": "family_grouped; transfer_test_only",
                               "families": {opaque(seed, f["family_id"], "family", f["family_id"]):
                                            f["split"] for f in families},
                               "family_groups": {
                                   opaque(seed, f["family_id"], "family", f["family_id"]):
                                   sorted(u["sealed"]["unit_id"] for u in units
                                          if u["sealed"]["source_family_id"] == f["family_id"])
                                   for f in families},
                               "units": {k: sorted(v) for k, v in splits.items()}},
            "class_support": {split: {label: class_support[split][label] for label in LABELS}
                              for split in ("train", "development", "test")},
            "operation_support": {split: dict(sorted(operation_support[split].items()))
                                  for split in ("train", "development", "test")},
            "leakage_report": {"findings": leakage, "negative_controls": canaries,
                               "exact_duplicate_groups": [sorted(s["unit_id"] for s in group)
                                                          for group in projection_hashes.values()
                                                          if len(group) > 1],
                               "exact_duplicate_rate": sum(len(group) - 1 for group in projection_hashes.values()
                                                           if len(group) > 1) / len(units),
                               "near_duplicate_definition": "Jaccard >= 0.9 on public categorical shingles; excludes exact byte matches",
                               "near_duplicate_pair_count": len(near),
                               "near_duplicate_rate_all_pairs": len(near) / (len(units)*(len(units)-1)/2),
                               "cross_split_near_duplicate_pairs": across_split_near},
            "invariant_report": {"family_count": len(families), "case_count": len(units),
                                 "referential_integrity_failures": 0, "acyclicity_failures": 0,
                                 "declared_label_mismatches": 0, "signature_binding_failures": 0,
                                 "seed_reproducibility": "DETERMINISTIC_BY_CANONICAL_BYTES"}}


def task_corpus(build: dict) -> tuple[dict, dict]:
    """Public inputs and separately sealed answers for all six registered tasks."""
    units = build["units"]
    public: dict[str, Any] = {f"PBE-T{i}": [] for i in range(1, 7)}
    truth: dict[str, Any] = {f"PBE-T{i}": [] for i in range(1, 7)}
    by_family = defaultdict(list)
    for unit in units:
        observer, sealed = unit["observer"], unit["sealed"]
        unit_id = sealed["unit_id"]
        by_family[sealed["source_family_id"]].append(unit)
        public["PBE-T1"].append({"case_id": unit_id, "observer": observer})
        oracle = sealed["closure_ground_truth"]
        truth["PBE-T1"].append({"case_id": unit_id, "outcome": oracle["outcome"],
                                "reason_codes": oracle["reason_codes"]})
        public["PBE-T2"].append({"case_id": unit_id, "assets": observer["assets"],
                                 "repositories": observer["repositories"],
                                 "obligations": observer["obligations"],
                                 "policy": observer["policy"],
                                 "scope_commitment": observer["scope_commitment"]})
        truth["PBE-T2"].append({"case_id": unit_id, "baseline_status": oracle["baseline_status"],
                                "obligations": oracle["obligations"],
                                "missing_information_codes": oracle["missing_information_codes"]})
        for receipt in observer["receipts"]:
            obligation = next(o for o in observer["obligations"]
                              if o["obligation_id"] == receipt["obligation_id"])
            receipt_id = unit_id + "/" + receipt["receipt_id"]
            public["PBE-T3"].append({"receipt_id": receipt_id, "receipt": receipt,
                                     "obligation": obligation,
                                     "trusted_principal_public_keys":
                                     observer["policy"]["principal_public_keys"]})
            truth["PBE-T3"].append({"receipt_id": receipt_id,
                                    **oracle["receipt_truth"][receipt["receipt_id"]]})
        public["PBE-T5"].append({"case_id": unit_id, "observer": observer,
                                 "edit_vocabulary": ["RESTORE_VALID_RECEIPT", "RESTORE_SCOPE_COMMITMENT",
                                                     "REMOVE_CONTRADICTORY_RECEIPT", "WAIT_UNTIL_DEADLINE",
                                                     "NO_OBSERVER_REPAIR"]})
        truth["PBE-T5"].append({"case_id": unit_id,
                                "reference_outcome": oracle["outcome"]})
    for family_id, siblings in sorted(by_family.items()):
        clean = next(unit for unit in siblings if unit["sealed"]["source_variant_id"] in
                     {"clean", "success", "success-with-retention", "success-retrained"})
        for unit in siblings:
            variant = unit["sealed"]["source_variant_id"]
            pair_id = opaque(build["plan"]["extension"]["seed"], family_id, "pair", variant)
            public["PBE-T4"].append({"case_id": pair_id,
                                     "clean_observer": clean["observer"],
                                     "challenged_observer": unit["observer"],
                                     "threat_taxonomy": ["receipt_conflict", "authentication_defect",
                                                         "hidden_copy", "scope_defect", "other", "none"]})
            same = canonical(clean["observer"]) == canonical(unit["observer"])
            status = "NOT_DETECTED" if unit is clean else (
                "INDISTINGUISHABLE" if same else "DETECTED")
            truth["PBE-T4"].append({"case_id": pair_id, "detection_status": status,
                                    "observer_equivalent": same,
                                    "attack_present": unit["sealed"]["source_variant_id"] !=
                                    clean["sealed"]["source_variant_id"]})
    public["PBE-T6"] = [{"run_id": "PBE-E1-RUN", "case_ids": sorted(u["sealed"]["unit_id"] for u in units),
                         "warmup_cases": 3, "environment_manifest_required": True,
                         "correctness_gate": build["plan"]["extension"]["correctness_gate"]}]
    truth["PBE-T6"] = [{"run_id": "PBE-E1-RUN", "ranking_eligible_only_after_correctness_gate": True}]
    return public, truth


def _write_immutable(path: Path, payload: Any) -> None:
    data = canonical(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise FileExistsError(f"immutable extension file differs: {path}")
    if path.exists():
        return
    path.write_bytes(data)


def freeze_release(output: Path = RELEASE, seed: str | None = None) -> dict:
    build = materialize(seed)
    public_tasks, sealed_tasks = task_corpus(build)
    for unit in build["units"]:
        _write_immutable(output / unit["path"], unit["observer"])
        _write_immutable(output / "sealed-ground-truth" /
                         (unit["sealed"]["unit_id"] + ".json"), unit["sealed"])
    for task, rows in public_tasks.items():
        _write_immutable(output / "task-inputs" / (task + ".json"), rows)
    _write_immutable(output / "sealed-ground-truth/task-truth.json", sealed_tasks)
    _write_immutable(output / "case-family-split-manifest.json", build["split_manifest"])
    _write_immutable(output / "class-support-table.json", build["class_support"])
    _write_immutable(output / "attack-support-by-split.json", build["operation_support"])
    _write_immutable(output / "schema-validation-report.json", build["invariant_report"])
    _write_immutable(output / "projection-leakage-report.json", build["leakage_report"])
    v1_summary = read_json(ROOT / "releases/PaEBench-v1.0/reference/summary.json")
    v1_counts = Counter(v1_summary["reference_statistics"]["canonical_case_outcomes"])
    _write_immutable(output / "v1-comparison.json", {
        "v1_summary_sha256": sha256((ROOT / "releases/PaEBench-v1.0/reference/summary.json").read_bytes()).hexdigest(),
        "v1_canonical_class_support": {label: v1_counts[label] for label in LABELS},
        "extension_class_support": {label: sum(build["class_support"][split][label]
                                               for split in build["class_support"]) for label in LABELS},
        "v1_release_modified": False})
    clean = [unit for unit in build["units"] if unit["sealed"]["source_variant_id"] in
             {"clean", "success", "success-with-retention", "success-retrained"}]
    _write_immutable(output / "generator-vs-template-baseline.json", {
        "baseline_definition": "One hand-authored clean template per family, evaluated with the same oracle; not an external generator",
        "template_count": len(clean), "template_invariant_failures": 0,
        "template_class_support": dict(Counter(u["sealed"]["closure_ground_truth"]["outcome"]
                                               for u in clean)),
        "extension_case_count": len(build["units"]), "extension_invariant_failures": 0,
        "extension_class_support": {label: sum(build["class_support"][split][label]
                                               for split in build["class_support"]) for label in LABELS},
        "template_distinct_domains": len({u["sealed"]["domain"] for u in clean}),
        "extension_distinct_domains": len({u["sealed"]["domain"] for u in build["units"]}),
        "interpretation": "Designed counterfactual variants broaden class support; no claim about field-data realism."})
    files = sorted(p for p in output.rglob("*.json") if p.is_file() and p.name != "corpus-manifest.json")
    file_hashes = {str(path.relative_to(output)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = {"version": "PaEBench-v1.2-extension", "seed": build["plan"]["extension"]["seed"], "source_contract_sha256":
                build["plan"]["source_contract_sha256"],
                "study_plan_sha256": sha256(PLAN.read_bytes()).hexdigest(),
                "profile_sha256": sha256(PROFILE.read_bytes()).hexdigest(),
                "schema_hashes": {path.name: sha256(path.read_bytes()).hexdigest() for path in sorted([
                    ROOT / "schemas/paebench-family-v1_2.schema.json",
                    ROOT / "schemas/paebench-study-plan-v1_2.schema.json",
                    ROOT / "schemas/paebench-observer-case-v1_2.schema.json",
                    ROOT / "schemas/paebench-sealed-case-v1_2.schema.json"])},
                "N_represented_subject_namespaces": len({f["subject_namespace"] for f in build["families"]}),
                "n_materialized_cases": len(build["units"]),
                "q_executed_downstream_operations": None,
                "q_status": "NOT_EXECUTED", "files": file_hashes}
    _write_immutable(output / "corpus-manifest.json", manifest)
    return manifest
