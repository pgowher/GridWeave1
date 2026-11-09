"""Oracle-blind VERCLO worker process for one PaEForge exchange."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
import time
from dataclasses import asdict
from typing import Any, Mapping, Sequence

from paeforge_contract import VercloInputAdapter, build_verclo_result, read_verifier_bundle
from paeforge_contract.canonical import sha256_digest
from paeforge_pipeline.io import utc_now, write_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="paeforge-verclo-worker")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policy-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--trust-context", type=Path, help="Explicit public GridWeave E2 trust configuration")
    parser.add_argument("--allow-synthetic-fixture", action='store_true', help="Explicit test-only synthetic backend")
    return parser


def evaluate_bundle(
    input_directory: str | Path,
    policy_directory: str | Path,
    *,
    source_revision: str,
    configuration_sha256: str,
    trust_context: str | Path | None = None,
    diagnostics_path: str | Path | None = None,
    allow_synthetic_fixture: bool = False,
) -> Mapping[str, Any]:
    """Evaluate one already isolated public bundle and return a frozen result.

    This function is intentionally kept in the verifier worker module: callers on
    the gateway side must never import it because importing the VERCLO runtime in
    the boundary process would weaken the deployment boundary.
    """

    started = time.perf_counter_ns()
    if trust_context is None and not allow_synthetic_fixture:
        raise ValueError('Explicit verification trust context is required; synthetic validation is test-only')
    manifest, observer, receipts = read_verifier_bundle(input_directory)
    adapter = VercloInputAdapter(manifest, observer, receipts)

    from erasure import FederatedClosureEvaluator  # type: ignore[import-not-found]
    from evidence import BackendValidation, CustodianReceiptVerifier, ExceptionValidation  # type: ignore[import-not-found]
    from proof import DeterministicValidationBackend, EvidenceGradeEvaluator  # type: ignore[import-not-found]
    from verclo import ErasureCaseManager, PolicyRegistry  # type: ignore[import-not-found]

    crypto_checks = exception_crypto_checks = None
    if trust_context is not None:
        from .native_dataset_backend import validation_facts
        context = json.loads(Path(trust_context).read_text())
        crypto_checks, exception_crypto_checks = validation_facts(observer, receipts, context)
    elif any(row['proof']['format'] == 'GRIDWEAVE-ED25519-E2-v1' for row in receipts['receipts']):
        raise ValueError('GridWeave signed receipts require explicit trusted public context')

    policies = PolicyRegistry.load(policy_directory)
    policy = policies.get(observer["policy"]["profile_id"])
    if policy.version != observer["policy"]["version"] or policy.sha256 != observer["policy"]["sha256"]:
        raise ValueError("run-local VERCLO policy does not match observer policy binding")
    manager = ErasureCaseManager(policies)
    case = manager.create_case_from_mapping(adapter.case_payload())
    case = manager.attach_topology(case.case_id, adapter.topology_view())
    exception_validations = []
    exception_admission_failures = []
    # An invalid scope can intentionally omit the obligation named by an
    # exception. The evaluator returns UNVERIFIABLE for that baseline before
    # considering evidence; do not attach assertions to its incomplete graph.
    for row in (observer["exceptions"] if case.graph is not None and case.graph.baseline_verifiable else ()):
        try:
            case = manager.assert_exception(
                case.case_id,
                row["obligation_id"],
                authority_principal_id=row["authority_principal_id"],
                basis_commitment=row["basis_commitment"],
                effective_at=datetime.fromisoformat(row["effective_at"].replace("Z", "+00:00")),
                expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")),
                exception_id=row["exception_id"],
            )
        except (ValueError, KeyError) as error:
            # An inadmissible assertion is rejected evidence, not a reason to
            # abort assessment of the remaining obligations in the dataset.
            exception_admission_failures.append({
                'exception_id': row['exception_id'], 'reason': str(error)})
            continue
        exception_validations.append(
            exception_crypto_checks[row["exception_id"]] if exception_crypto_checks is not None
            else ExceptionValidation(row["exception_id"], True, True, True))

    if crypto_checks is None:
        validations = {}
        for receipt_id, proof in adapter.verification_material().items():
            supported = (
                proof["format"] == "PAEGEN-SYNTHETIC-ORDERED-V1"
                and bool(proof["verification_material_refs"])
            )
            validations[receipt_id] = BackendValidation(
                backend_name="deterministic-public-fixture-v1",
                verification_material_available=supported,
                credential_valid_at_event=supported and bool(proof.get("credential_ref")),
                authenticator_valid=supported and bool(proof.get("credential_ref")),
                anchor_valid=supported and bool(proof.get("anchor_ref")),
                ordering_support_valid=supported and bool(proof.get("anchor_ref")),
                mechanism_present=bool(proof.get("mechanism_ref")),
                mechanism_valid=supported and bool(proof.get("mechanism_ref")),
                assumptions_valid=supported,
                diagnostics=("SYNTHETIC_PUBLIC_FIXTURE_BACKEND",),
            )
    else:
        validations = crypto_checks
    backend = DeterministicValidationBackend(validations)
    receipt_verifier = CustodianReceiptVerifier(backend)
    evaluator = FederatedClosureEvaluator(EvidenceGradeEvaluator(receipt_verifier), policies)
    evaluation_time = datetime.fromisoformat(observer["evaluation_time"].replace("Z", "+00:00"))
    report = evaluator.evaluate(
        case,
        adapter.receipts(),
        evaluation_time,
        exception_validations=exception_validations,
        open_challenge_ids=adapter.open_challenge_ids(),
    )
    elapsed = time.perf_counter_ns() - started
    obligation_count = 0 if case.graph is None else len(case.graph.obligations)
    receipt_count = len(receipts["receipts"])
    executed_q = 2 + obligation_count + receipt_count
    result = build_verclo_result(
        report=report,
        manifest=manifest,
        observer_projection=observer,
        receipt_stream=receipts,
        evaluated_at=evaluation_time,
        execution={
            "executed_operations_q": executed_q,
            "duration_ns": elapsed,
            "backend_id": "gridweave-ed25519-e2-v1" if crypto_checks is not None else "deterministic-public-fixture-v1",
            "configuration_sha256": configuration_sha256,
        },
        provenance={
            "producer": "VERCLO",
            "producer_version": __import__('verclo').__version__,
            "source_revision": source_revision,
            "frozen_at": utc_now(),
        },
    )
    if diagnostics_path is not None:
        graph = case.graph
        obligations = {} if graph is None else {o.obligation_id: o for o in graph.obligations}
        checks = []
        for receipt in adapter.receipts():
            obligation = obligations.get(receipt.obligation_id)
            if obligation is None:
                checks.append({'receipt_id': receipt.receipt_id, 'status': 'OUTSIDE_DISCOVERED_SCOPE'})
            else:
                checks.append(asdict(receipt_verifier.verify(receipt, obligation, evaluation_time)))
        details = {'case_id': case.case_id, 'graph': None if graph is None else asdict(graph),
                   'receipt_checks': checks,
                   'exception_admission_failures': exception_admission_failures,
                   'evidence_bundles': [asdict(r.evidence) for r in report.obligation_results if r.evidence],
                   'logical_workload': {'discovered_obligations': obligation_count, 'input_receipts': receipt_count,
                                        'executed_operations_q': executed_q,
                                        'definition': '2 document adapters + discovered obligations + input receipts; not CPU operations'},
                   'trust_profile': 'CONFIGURED_SYNTHETIC_ED25519_E2' if crypto_checks is not None else 'TEST_FIXTURE',
                   'physical_destruction_concluded': False}
        encoded = json.loads(json.dumps(details, default=lambda x: x.isoformat()))
        write_json(Path(diagnostics_path), encoded)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = evaluate_bundle(
        args.input,
        args.policy_directory,
        source_revision=args.source_revision,
        configuration_sha256=args.configuration_sha256,
        trust_context=args.trust_context,
        allow_synthetic_fixture=args.allow_synthetic_fixture,
    )
    write_json(args.output, result)
    print(
        f"case_id={result['case_id']} closure={result['closure_class']} "
        f"q={result['execution']['executed_operations_q']} result_sha256={sha256_digest(result)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
