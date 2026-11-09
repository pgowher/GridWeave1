"""Oracle-blind VERCLO worker process for one PaEForge exchange."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
import time
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
    return parser


def evaluate_bundle(
    input_directory: str | Path,
    policy_directory: str | Path,
    *,
    source_revision: str,
    configuration_sha256: str,
    trust_context: str | Path | None = None,
) -> Mapping[str, Any]:
    """Evaluate one already isolated public bundle and return a frozen result.

    This function is intentionally kept in the verifier worker module: callers on
    the gateway side must never import it because importing the VERCLO runtime in
    the boundary process would weaken the deployment boundary.
    """

    started = time.perf_counter_ns()
    manifest, observer, receipts = read_verifier_bundle(input_directory)
    adapter = VercloInputAdapter(manifest, observer, receipts)

    from erasure import FederatedClosureEvaluator  # type: ignore[import-not-found]
    from evidence import BackendValidation, CustodianReceiptVerifier, ExceptionValidation  # type: ignore[import-not-found]
    from proof import DeterministicValidationBackend, EvidenceGradeEvaluator  # type: ignore[import-not-found]
    from verclo import ErasureCaseManager, PolicyRegistry  # type: ignore[import-not-found]

    crypto_checks = exception_crypto_checks = None
    if trust_context is not None:
        from .gridweave_backend import validation_facts
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
    for row in observer["exceptions"]:
        case = manager.assert_exception(
            case.case_id,
            row["obligation_id"],
            authority_principal_id=row["authority_principal_id"],
            basis_commitment=row["basis_commitment"],
            effective_at=datetime.fromisoformat(row["effective_at"].replace("Z", "+00:00")),
            expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")),
            exception_id=row["exception_id"],
        )
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
    evaluator = FederatedClosureEvaluator(
        EvidenceGradeEvaluator(CustodianReceiptVerifier(backend)), policies
    )
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
            "producer_version": "1.0.0",
            "source_revision": source_revision,
            "frozen_at": utc_now(),
        },
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = evaluate_bundle(
        args.input,
        args.policy_directory,
        source_revision=args.source_revision,
        configuration_sha256=args.configuration_sha256,
        trust_context=args.trust_context,
    )
    write_json(args.output, result)
    print(
        f"case_id={result['case_id']} closure={result['closure_class']} "
        f"q={result['execution']['executed_operations_q']} result_sha256={sha256_digest(result)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
