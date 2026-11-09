from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest
from jsonschema import ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROPOSAL_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROPOSAL_ROOT / "HTGLThesis" / "src"))

from erasure import FederatedClosureEvaluator  # noqa: E402
from evidence import BackendValidation, CustodianReceiptVerifier  # noqa: E402
from paeforge_contract import (  # noqa: E402
    ContractError,
    LeakageError,
    VercloInputAdapter,
    build_case_manifest,
    build_observer_projection,
    build_receipt_stream,
    build_verclo_result,
    read_verifier_bundle,
    sha256_digest,
    validate_document,
    validate_verifier_bundle,
    validate_verifier_input,
    verclo_obligation_id,
    write_verifier_bundle,
)
from paeforge_contract.evaluator import build_evaluation_report  # noqa: E402
from proof import DeterministicValidationBackend, EvidenceGradeEvaluator  # noqa: E402
from verclo import ErasureCaseManager  # noqa: E402
from verclo.canonical import commitment, content_id  # noqa: E402
from verclo.policy import PolicyRegistry  # noqa: E402


UTC = timezone.utc
ACCEPTED = datetime(2026, 1, 1, tzinfo=UTC)
EVALUATED = datetime(2026, 2, 2, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _documents():
    policies = PolicyRegistry.load()
    policy = policies.get("VERCLO-POLICY-TECHNICAL-ERASURE")
    seed = {
        "derivation": "NAMED_STREAM_SHA256_V1",
        "replicate_id": 7,
        "master_seed_commitment": DIGEST_A,
        "seed_stream_digest": DIGEST_B,
    }
    policy_ref = {"profile_id": policy.profile_id, "version": policy.version, "sha256": policy.sha256}
    topology = {
        "scope_version": 1,
        "graph_available": True,
        "declared_scope_complete": True,
        "unresolved_reference_ids": [],
        "assets": [
            {"asset_id": "ASSET-1", "dataset_id": "DATASET-1", "asset_kind": "interval_reading", "visibility": "DECLARED"}
        ],
        "repositories": [
            {"repository_id": "REPO-1", "organization_id": "ORG-1", "custodian_principal_id": "CUSTODIAN-1", "repository_class": "PRIMARY_STORE", "visibility": "DECLARED"}
        ],
        "replicas": [
            {"replica_id": "REPLICA-1", "asset_id": "ASSET-1", "repository_id": "REPO-1", "replica_class": "primary", "visibility": "DECLARED"}
        ],
        "lineage_edges": [],
    }
    scope_material = {
        "case_id": "CASE-1",
        "dataset_id": "DATASET-1",
        "correlation_id": "CORR-1",
        "scope_version": 1,
        "assets": topology["assets"],
        "repositories": topology["repositories"],
        "replicas": topology["replicas"],
        "lineage_edges": topology["lineage_edges"],
    }
    topology["scope_commitment"] = commitment("verclo-visible-scope-v1", scope_material)
    case = {
        "dataset_id": "DATASET-1",
        "correlation_id": "CORR-1",
        "request_id": "REQUEST-1",
        "requester_principal_id": "REQUESTER-1",
        "root_asset_ids": ["ASSET-1"],
        "accepted_at": "2026-01-01T00:00:00Z",
        "metadata": {"observer_note": "sanitized"},
    }
    provenance = {
        "producer": "PaEGen",
        "producer_version": "1.0.0",
        "source_revision": "paegen-test-revision",
        "source_bundle_sha256": DIGEST_C,
    }
    observer = build_observer_projection(
        exchange_id="EXCHANGE-1",
        run_id="RUN-1",
        scenario_id="SCENARIO-1",
        case_id="CASE-1",
        seed=seed,
        produced_at=ACCEPTED,
        evaluation_time=EVALUATED,
        observer={"principal_id": "AUDITOR-1", "roles": ["AUDITOR"], "profile_id": "OBSERVER-RESTRICTED", "profile_version": "1.0.0", "access_class": "restricted"},
        policy=policy_ref,
        case=case,
        topology=topology,
        provenance=provenance,
    )
    identity = {
        "case_id": "CASE-1",
        "dataset_id": "DATASET-1",
        "correlation_id": "CORR-1",
        "asset_id": "ASSET-1",
        "replica_id": "REPLICA-1",
        "repository_id": "REPO-1",
        "custodian_principal_id": "CUSTODIAN-1",
        "policy_profile_id": policy.profile_id,
        "policy_version": policy.version,
    }
    obligation_id = verclo_obligation_id(
        **identity,
    )
    assert obligation_id == content_id("OBL", "verclo-obligation-v1", identity)
    receipts = build_receipt_stream(
        exchange_id="EXCHANGE-1",
        run_id="RUN-1",
        scenario_id="SCENARIO-1",
        case_id="CASE-1",
        seed=seed,
        stream_id="STREAM-1",
        receipts=[
            {
                "receipt_id": "RECEIPT-1",
                "case_id": "CASE-1",
                "obligation_id": obligation_id,
                "asset_id": "ASSET-1",
                "replica_id": "REPLICA-1",
                "repository_id": "REPO-1",
                "issuer_principal_id": "CUSTODIAN-1",
                "issuer_role": "CUSTODIAN",
                "trust_domain": "TRUST-1",
                "fault_domain": "FAULT-1",
                "evidence_type": "signature",
                "disposition": "ERASED",
                "event_time": "2026-01-02T00:00:00Z",
                "submitted_at": "2026-01-02T00:01:00Z",
                "not_before": "2026-01-01T00:00:00Z",
                "provenance_refs": ["C-PAE-MESSAGE-1"],
                "claim_commitment": DIGEST_A,
                "proof": {
                    "format": "JWS-DETACHED",
                    "verification_material_refs": ["DID-KEY-1"],
                    "credential_ref": "DID-KEY-1",
                },
            }
        ],
        provenance=provenance,
    )
    manifest = build_case_manifest(
        exchange_id="EXCHANGE-1",
        run_id="RUN-1",
        scenario_id="SCENARIO-1",
        case_id="CASE-1",
        seed=seed,
        policy=policy_ref,
        observer_projection=observer,
        receipt_stream=receipts,
        provenance={
            "producer": "PaEGen",
            "producer_version": "1.0.0",
            "source_revision": "paegen-test-revision",
            "generated_at": "2026-01-01T00:00:00Z",
        },
    )
    return manifest, observer, receipts, obligation_id, policies


def _run_verclo():
    manifest, observer, receipts, obligation_id, policies = _documents()
    adapter = VercloInputAdapter(manifest, observer, receipts)
    manager = ErasureCaseManager(policies)
    case = manager.create_case_from_mapping(adapter.case_payload())
    case = manager.attach_topology(case.case_id, adapter.topology_view())
    assert case.graph is not None
    assert [row.obligation_id for row in case.graph.obligations] == [obligation_id]
    backend = DeterministicValidationBackend(
        {"RECEIPT-1": BackendValidation("fixture", authenticator_valid=True)}
    )
    evaluator = FederatedClosureEvaluator(
        EvidenceGradeEvaluator(CustodianReceiptVerifier(backend)), policies
    )
    report = evaluator.evaluate(case, adapter.receipts(), EVALUATED)
    return manifest, observer, receipts, report, obligation_id


def test_all_exchange_and_transport_schemas_are_valid_and_registered() -> None:
    schema_files = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
    assert len(schema_files) == 8
    manifest, observer, receipts, _, _ = _documents()
    for document in (manifest, observer, receipts):
        validate_document(document)


def test_bundle_round_trip_is_canonical_and_immutable(tmp_path: Path) -> None:
    manifest, observer, receipts, _, _ = _documents()
    paths = write_verifier_bundle(tmp_path, manifest, observer, receipts)
    assert [path.name for path in paths] == [
        "case-manifest.json",
        "observer-projection.json",
        "receipt-stream.json",
    ]
    assert read_verifier_bundle(tmp_path) == (manifest, observer, receipts)
    write_verifier_bundle(tmp_path, manifest, observer, receipts)
    changed = deepcopy(observer)
    changed["observer"]["principal_id"] = "OTHER"
    with pytest.raises((ContractError, FileExistsError)):
        write_verifier_bundle(tmp_path, manifest, changed, receipts)


def test_bundle_reader_rejects_an_evaluator_file_in_verifier_directory(tmp_path: Path) -> None:
    manifest, observer, receipts, _, _ = _documents()
    write_verifier_bundle(tmp_path, manifest, observer, receipts)
    (tmp_path / "ground-truth.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ContractError, match="inventory mismatch"):
        read_verifier_bundle(tmp_path)


@pytest.mark.parametrize(
    "field",
    [
        "closure_ground_truth",
        "expectedOutcome",
        "verification-status-truth",
        "expected_obligations",
        "policy_decision_truth",
        "worldDisposition",
        "hidden_topology",
        "attack_label",
        "protected_identifier_mapping",
        "receipt_validity_truth",
    ],
)
def test_boundary_rejects_privileged_fields_at_any_depth(field: str) -> None:
    _, observer, _, _, _ = _documents()
    contaminated = deepcopy(observer)
    contaminated["case"]["metadata"][field] = "ORACLE-CANARY"
    with pytest.raises(LeakageError):
        validate_verifier_input(contaminated)


def test_boundary_rejects_oracle_canary_even_under_safe_key() -> None:
    _, observer, _, _, _ = _documents()
    contaminated = deepcopy(observer)
    contaminated["case"]["metadata"]["note"] = "UNIQUE-ORACLE-CANARY"
    with pytest.raises(LeakageError):
        validate_verifier_input(contaminated, canary_values=("UNIQUE-ORACLE-CANARY",))


def test_schema_allowlist_rejects_unknown_nontruth_field() -> None:
    _, observer, _, _, _ = _documents()
    contaminated = deepcopy(observer)
    contaminated["unreviewed_extension"] = "value"
    with pytest.raises(ValidationError):
        validate_verifier_input(contaminated)


def test_cross_file_identifiers_seed_sequence_and_hashes_are_enforced() -> None:
    manifest, observer, receipts, _, _ = _documents()
    changed = deepcopy(receipts)
    changed["seed"]["replicate_id"] = 8
    with pytest.raises(ContractError, match="replicate_id"):
        validate_verifier_bundle(manifest, observer, changed)
    changed = deepcopy(receipts)
    changed["receipts"][0]["sequence"] = 1
    changed["stream_commitment"] = commitment("irrelevant", [])
    with pytest.raises(ContractError):
        validate_verifier_bundle(manifest, observer, changed)
    changed = deepcopy(manifest)
    changed["artifacts"]["observer_projection"]["sha256"] = DIGEST_A
    with pytest.raises(ContractError, match="digest"):
        validate_verifier_bundle(changed, observer, receipts)


def test_verclo_adapter_executes_without_evaluator_truth() -> None:
    _, _, _, report, obligation_id = _run_verclo()
    assert report.closure_class.value == "CLOSED"
    assert report.covered_obligation_ids == (obligation_id,)
    assert report.physical_destruction_concluded is False


def test_result_is_frozen_then_compared_by_evaluator_only_adapter() -> None:
    manifest, observer, receipts, report, obligation_id = _run_verclo()
    result = build_verclo_result(
        report=report,
        manifest=manifest,
        observer_projection=observer,
        receipt_stream=receipts,
        evaluated_at=EVALUATED,
        execution={
            "executed_operations_q": 1,
            "duration_ns": 1000,
            "backend_id": "deterministic-local-v1",
            "configuration_sha256": DIGEST_C,
        },
        provenance={
            "producer": "VERCLO",
            "producer_version": "1.0.0",
            "source_revision": "verclo-test-revision",
            "frozen_at": "2026-02-02T00:00:01Z",
        },
    )
    validate_document(result)
    with pytest.raises(ContractError):
        validate_verifier_input(result)
    truth = {
        "access_class": "evaluator_only",
        "run_id": "RUN-1",
        "scenario_id": "SCENARIO-1",
        "replicate_id": 7,
        "seed_stream_digest": DIGEST_B,
        "cases": [
            {
                "case_id": "CASE-1",
                "obligation_graph": {"obligations": [{"obligation_id": obligation_id}]},
                "closure_ground_truth": {"outcome": "CLOSED"},
            }
        ],
    }
    evaluation = build_evaluation_report(
        sealed_truth=truth,
        verclo_result=result,
        evaluated_at="2026-02-02T00:00:02Z",
        visibility_attribution="NONE",
        provenance={
            "producer": "PaEBench",
            "producer_version": "1.0.0",
            "source_revision": "paebench-test-revision",
            "generated_at": "2026-02-02T00:00:02Z",
            "verclo_result_frozen_before_truth_open": True,
        },
    )
    assert evaluation["classification"] == "MATCH"
    assert evaluation["metrics"]["false_closure"] is False
    assert evaluation["inputs"]["verclo_result_sha256"] == sha256_digest(result)


def test_verclo_boundary_module_has_no_generator_or_evaluator_import() -> None:
    forbidden = {"htgl_dataset_generator", "evaluator", "oracle", "paegen"}
    for filename in ("adapters.py", "exchange.py", "validation.py", "leakage.py"):
        path = PROJECT_ROOT / "src" / "paeforge_contract" / filename
        imported = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not imported & forbidden, path


def test_physical_destruction_claim_is_schema_forbidden() -> None:
    manifest, observer, receipts, report, _ = _run_verclo()
    result = build_verclo_result(
        report=report,
        manifest=manifest,
        observer_projection=observer,
        receipt_stream=receipts,
        evaluated_at=EVALUATED,
        execution={"executed_operations_q": 1, "duration_ns": 1, "backend_id": "local", "configuration_sha256": DIGEST_A},
        provenance={"producer": "VERCLO", "producer_version": "1.0.0", "source_revision": "revision", "frozen_at": "2026-02-02T00:00:01Z"},
    )
    result["physical_destruction_concluded"] = True
    with pytest.raises(ValidationError):
        validate_document(result)
