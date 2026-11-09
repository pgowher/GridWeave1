from __future__ import annotations

import ast
import csv
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analytics import ClosureClass  # noqa: E402
from erasure import FederatedClosureEvaluator  # noqa: E402
from evidence import BackendValidation, CustodianReceipt, CustodianReceiptVerifier, ExceptionValidation  # noqa: E402
from proof import (  # noqa: E402
    BundleStatus,
    DeterministicValidationBackend,
    EvidenceGradeEvaluator,
    PBFTValidationBackend,
    PBFTValidationCertificate,
)
from verclo.models import (  # noqa: E402
    CasePhase, ErasureCase, ExceptionAssertion, Obligation, ObligationGraph,
)
from verclo.policy import PolicyRegistry  # noqa: E402


UTC = timezone.utc
ACCEPTED = datetime(2026, 8, 1, tzinfo=UTC)
DEADLINE = datetime(2026, 9, 15, tzinfo=UTC)
EVALUATION = datetime(2026, 9, 16, tzinfo=UTC)


def obligation(number: int, *, grade: str = "E2") -> Obligation:
    return Obligation(
        obligation_id=f"OBL-{number}", case_id="CASE-TEMPLATE", dataset_id="DATASET-1",
        correlation_id="CORR-1", asset_id=f"ASSET-{number}", replica_id=f"REPLICA-{number}",
        repository_id=f"REPO-{number}", custodian_principal_id=f"CUSTODIAN-{number}",
        deadline=DEADLINE, minimum_evidence_grade=grade,
        permitted_dispositions=("CRYPTO_ERASED", "ERASED"),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE", policy_version="1.0.0",
    )


def make_case(case_id: str, *, baseline: bool = True, count: int = 2, exception: bool = False) -> ErasureCase:
    obligations = tuple(replace(obligation(i), case_id=case_id) for i in range(1, count + 1))
    exceptions = ()
    if exception and obligations:
        exceptions = (ExceptionAssertion(
            exception_id="EX-2", obligation_id=obligations[-1].obligation_id,
            authority_principal_id="AUTHORITY-RETENTION-REVIEW", basis_commitment="a" * 64,
            effective_at=ACCEPTED, expires_at=EVALUATION + timedelta(days=1),
        ),)
    graph = ObligationGraph(
        case_id=case_id, dataset_id="DATASET-1", correlation_id="CORR-1", scope_version=1,
        root_asset_ids=("ASSET-1",), discovered_asset_ids=tuple(row.asset_id for row in obligations),
        relationship_ids=(), obligations=obligations, exceptions=exceptions,
        custodians=tuple(row.custodian_principal_id for row in obligations),
        scope_commitment="a" * 64, obligation_commitment="b" * 64,
        baseline_verifiable=baseline,
        baseline_reason_codes=() if baseline else ("OBLIGATION_COMMITMENT_MISMATCH",),
    )
    return ErasureCase(
        case_id=case_id, run_id="RUN-1", dataset_id="DATASET-1", correlation_id="CORR-1",
        request_id="REQ-1", requester_principal_id="REQUESTER-1", root_asset_ids=("ASSET-1",),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE", accepted_at=ACCEPTED,
        phase=CasePhase.OBLIGATIONS_ACTIVE, revision=1, graph=graph,
    )


def receipt(
    row: Obligation, receipt_id: str, *, evidence_type: str = "signature",
    disposition: str = "ERASED", event_time: datetime = ACCEPTED,
    issuer: str | None = None, role: str = "CUSTODIAN",
    trust_domain: str = "TD-CUSTODIAN", fault_domain: str = "FD-CUSTODIAN",
    canonical: bool = True, provenance: bool = True,
) -> CustodianReceipt:
    return CustodianReceipt(
        receipt_id=receipt_id, case_id=row.case_id, obligation_id=row.obligation_id,
        asset_id=row.asset_id, replica_id=row.replica_id, repository_id=row.repository_id,
        issuer_principal_id=issuer or row.custodian_principal_id, issuer_role=role,
        trust_domain=trust_domain, fault_domain=fault_domain, evidence_type=evidence_type,
        disposition=disposition, event_time=event_time, submitted_at=event_time,
        not_before=ACCEPTED, provenance_refs=("PROV-1",) if provenance else (),
        canonical_payload_valid=canonical, obligation_bound=True,
    )


class EvidenceAndClosureTests(unittest.TestCase):
    def _services(self, validations=None):
        backend = DeterministicValidationBackend(validations, allow_unlisted_for_tests=True)
        verifier = CustodianReceiptVerifier(backend)
        grades = EvidenceGradeEvaluator(verifier)
        closure = FederatedClosureEvaluator(grades, PolicyRegistry.load())
        return verifier, grades, closure

    def test_receipt_rejection_precedence_and_late_downgrade(self) -> None:
        row = obligation(1)
        validations = {
            "BAD": BackendValidation("fixture", authenticator_valid=False),
            "LATE": BackendValidation("fixture"),
        }
        verifier, _, _ = self._services(validations)
        malformed = receipt(row, "BAD", canonical=False, provenance=False)
        self.assertEqual("MALFORMED_CANONICAL_PAYLOAD", verifier.verify(malformed, row, EVALUATION).rejection_reason)
        bad_auth = receipt(row, "BAD")
        self.assertEqual("INVALID_AUTHENTICATOR", verifier.verify(bad_auth, row, EVALUATION).rejection_reason)
        late = verifier.verify(receipt(row, "LATE", event_time=DEADLINE + timedelta(seconds=1)), row, EVALUATION)
        self.assertEqual("E2", late.grade)
        self.assertIn("LATE_FOR_OBLIGATION", late.downgrade_reasons)
        self.assertFalse(late.closure_admissible)

    def test_e0_to_e5_are_capability_based_and_never_claim_physical_destruction(self) -> None:
        row = obligation(1)
        receipts = {
            "digest": receipt(row, "DIGEST", evidence_type="digest", disposition="UNREACHABLE"),
            "signature": receipt(row, "SIGNATURE"),
            "inclusion": receipt(row, "INCLUSION", evidence_type="inclusion_proof", disposition="UNREACHABLE", issuer="LOG"),
            "mechanism": receipt(row, "MECHANISM", evidence_type="deletion_acknowledgement"),
            "audit1": receipt(row, "AUDIT-1", evidence_type="audit_finding", issuer="AUDITOR-1", role="AUDITOR", trust_domain="TD-A1", fault_domain="FD-A1"),
            "audit2": receipt(row, "AUDIT-2", evidence_type="audit_finding", issuer="AUDITOR-2", role="AUDITOR", trust_domain="TD-A2", fault_domain="FD-A2"),
        }
        validations = {
            "INCLUSION": BackendValidation("fixture", anchor_valid=True),
            "MECHANISM": BackendValidation("fixture", ordering_support_valid=True, mechanism_present=True, mechanism_valid=True, mechanism_expires_at=EVALUATION + timedelta(days=1)),
        }
        receipts['signature'] = replace(receipts['signature'], claim_commitment='c'*64)
        receipts['inclusion'] = replace(receipts['inclusion'], provenance_refs=(
            'PROV-1', 'receipt:SIGNATURE', 'claim:'+'c'*64))
        _, grades, _ = self._services(validations)
        cases = (
            ("E0", [], None, []),
            ("E1", [receipts["digest"]], "DIGEST", []),
            ("E2", [receipts["signature"]], "SIGNATURE", []),
            ("E3", [receipts["signature"], receipts["inclusion"]], "SIGNATURE", ["INCLUSION"]),
            ("E4", [receipts["mechanism"]], "MECHANISM", []),
            ("E5", [receipts["mechanism"], receipts["audit1"], receipts["audit2"]], "MECHANISM", ["AUDIT-1", "AUDIT-2"]),
        )
        for expected, rows, primary, support in cases:
            with self.subTest(grade=expected):
                result = grades.evaluate(row, rows, EVALUATION, primary_receipt_id=primary, support_receipt_ids=support, required_grade=expected)
                self.assertEqual(BundleStatus.GRADED, result.status)
                self.assertEqual(expected, result.grade)
                self.assertFalse(result.physical_destruction_concluded)

    def test_conflicting_admissible_terminal_assertions_are_disputed(self) -> None:
        row = obligation(1)
        _, grades, _ = self._services()
        result = grades.evaluate(row, (receipt(row, "OK"), receipt(row, "NO", disposition="FAILED")), EVALUATION)
        self.assertEqual(BundleStatus.DISPUTED, result.status)
        self.assertEqual(("NO", "OK"), result.contradictory_receipt_ids)

    def test_approved_phase_2_evidence_grade_suite_matches_exactly(self) -> None:
        proposal_root = PROJECT_ROOT.parent
        suite = json.loads((PROJECT_ROOT / "tests/fixtures/evidence_grade_cases_v1.json").read_text())
        formal_root = PROJECT_ROOT / "tests/fixtures/formal"
        with (formal_root / "Receipt_Grade_Manual_Evaluation.csv").open(newline="", encoding="utf-8") as handle:
            receipt_expected = {row["receipt_id"]: row for row in csv.DictReader(handle)}
        with (formal_root / "Bundle_Grade_Manual_Evaluation.csv").open(newline="", encoding="utf-8") as handle:
            bundle_expected = {row["bundle_id"]: row for row in csv.DictReader(handle)}

        def merged(base, override):
            result = deepcopy(base)
            for key, value in override.items():
                result[key] = merged(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else deepcopy(value)
            return result

        def timestamp(value):
            return None if value is None else datetime.fromisoformat(value.replace("Z", "+00:00"))

        raw_rows = [merged(suite["receipt_defaults"], row) for row in suite["receipts"]]
        validations = {
            row["receipt_id"]: BackendValidation(
                "phase-2-conformance", row["verification_material_available"],
                row["credential_valid_at_event"], row["authenticator_valid"],
                row["anchor_valid"], row["ordering_support_valid"],
                row["mechanism"]["present"], row["mechanism"]["valid"],
                timestamp(row["mechanism"].get("expires_at")),
            ) for row in raw_rows
        }
        evidence_rows = []
        for row in raw_rows:
            evidence_rows.append(CustodianReceipt(
                receipt_id=row["receipt_id"], case_id="CASE-GRADE", obligation_id="O1",
                asset_id="ASSET-GRADE", replica_id="REPLICA-GRADE", repository_id="REPO-GRADE",
                issuer_principal_id=row["issuer_id"], issuer_role=row["issuer_role"],
                trust_domain=row["trust_domain"], fault_domain=row["fault_domain"],
                evidence_type=row["evidence_type"], disposition=row["disposition"],
                event_time=timestamp(row["event_time"]), submitted_at=timestamp(row["event_time"]),
                not_before=timestamp(row["not_before"]), expires_at=timestamp(row.get("expires_at")),
                provenance_refs=tuple(row.get('provenance_refs', ('PROV-1',))) if row["provenance_complete"] else (),
                canonical_payload_valid=row["canonical_valid"], obligation_bound=row["obligation_bound"],
                claim_commitment=row.get('claim_commitment',''),
            ))
        row = replace(
            obligation(1), obligation_id="O1", case_id="CASE-GRADE", asset_id="ASSET-GRADE",
            replica_id="REPLICA-GRADE", repository_id="REPO-GRADE",
            permitted_dispositions=("APPROVED_TRANSFORM", "CRYPTO_ERASED", "ERASED"),
            deadline=timestamp(suite["receipt_defaults"]["obligation_deadline"]),
        )
        verifier, grades, _ = self._services(validations)
        by_id = {item.receipt_id: item for item in evidence_rows}
        evaluation_time = timestamp(suite["receipt_defaults"]["evaluation_time"])
        for item in evidence_rows:
            with self.subTest(receipt_id=item.receipt_id):
                observed = verifier.verify(item, row, evaluation_time)
                expected = receipt_expected[item.receipt_id]
                self.assertEqual(expected["manual_status"], observed.status)
                self.assertEqual(expected["manual_grade"] or None, observed.grade)
                self.assertEqual(expected["rejection_reason"] or None, observed.rejection_reason)
                self.assertEqual(tuple((expected["downgrade_reasons"] or "").split("|") if expected["downgrade_reasons"] else ()), observed.downgrade_reasons)
                self.assertEqual(expected["closure_admissible"] == "true", observed.closure_admissible)
                self.assertEqual(expected["manual_conclusion"] or None, observed.conclusion)
                self.assertFalse(observed.physical_destruction_concluded)

        for bundle in suite["bundles"]:
            with self.subTest(bundle_id=bundle["bundle_id"]):
                observed = grades.evaluate(
                    row, tuple(by_id.values()), evaluation_time,
                    primary_receipt_id=bundle.get("primary_receipt_id"),
                    support_receipt_ids=bundle.get("support_receipt_ids", ()),
                    required_grade=bundle["required_grade"],
                    required_corroborators=int(bundle.get("required_corroborators", 0)),
                    required_independent_domains=int(bundle.get("required_independent_domains", 0)),
                )
                expected = bundle_expected[bundle["bundle_id"]]
                self.assertEqual(expected["manual_status"], observed.status)
                self.assertEqual(expected["manual_grade"] or None, observed.grade)
                self.assertEqual(expected["reason"] or None, observed.reason)
                self.assertEqual(tuple((expected["downgrade_reasons"] or "").split("|") if expected["downgrade_reasons"] else ()), observed.downgrade_reasons)
                self.assertEqual(tuple((expected["missing_receipt_ids"] or "").split("|") if expected["missing_receipt_ids"] else ()), observed.missing_receipt_ids)
                self.assertEqual(expected["manual_conclusion"] or None, observed.conclusion)
                self.assertFalse(observed.physical_destruction_concluded)

    def test_model_derived_closure_conformance_suite(self) -> None:
        fixture = json.loads((PROJECT_ROOT / "tests/fixtures/verclo_closure_conformance_v1.json").read_text())
        for spec in fixture["cases"]:
            with self.subTest(case_id=spec["case_id"]):
                mode = spec["mode"]
                case = make_case(
                    spec["case_id"], baseline=mode != "invalid_baseline",
                    count=0 if mode == "no_applicable" else 2,
                    exception=mode == "covered_and_excepted",
                )
                rows = case.graph.obligations
                evidence_rows: list[CustodianReceipt] = []
                validations = {}
                exception_checks = []
                evaluation = ACCEPTED if mode == "before_deadline" else EVALUATION
                if mode in {"covered_all", "covered_and_excepted"}:
                    evidence_rows.append(receipt(rows[0], "R-1"))
                    if mode == "covered_all":
                        evidence_rows.append(receipt(rows[1], "R-2"))
                    else:
                        exception_checks.append(ExceptionValidation("EX-2", True, True))
                elif mode == "covered_one":
                    evidence_rows.append(receipt(rows[0], "R-1"))
                elif mode == "contradictory":
                    evidence_rows.extend((receipt(rows[0], "R-OK"), receipt(rows[0], "R-NO", disposition="FAILED")))
                elif mode == "late_all":
                    evidence_rows.extend(receipt(row, f"R-LATE-{i}", event_time=DEADLINE + timedelta(seconds=1)) for i, row in enumerate(rows))
                elif mode == "invalid_all":
                    for i, row in enumerate(rows):
                        row_id = f"R-BAD-{i}"
                        evidence_rows.append(receipt(row, row_id))
                        validations[row_id] = BackendValidation("fixture", authenticator_valid=False)
                _, _, closure = self._services(validations)
                report = closure.evaluate(case, evidence_rows, evaluation, exception_validations=exception_checks)
                self.assertEqual(spec["expected"], report.closure_class)
                self.assertFalse(report.physical_destruction_concluded)
                self.assertEqual("CLOSURE_RELATIVE_TO_AUTHENTICATED_OBSERVABLE_SCOPE", report.visibility_limitation)
                if mode == "late_all":
                    self.assertEqual(tuple(row.obligation_id for row in rows), report.late_obligation_ids)
                if mode == "invalid_all":
                    self.assertEqual(tuple(row.obligation_id for row in rows), report.invalid_obligation_ids)

    def test_invalid_exception_is_not_treated_as_resolution(self) -> None:
        case = make_case("CASE-INVALID-EX", count=1, exception=True)
        _, _, closure = self._services()
        report = closure.evaluate(case, (), EVALUATION, exception_validations=(ExceptionValidation("EX-2", False, True),))
        self.assertEqual(ClosureClass.OPEN, report.closure_class)
        self.assertEqual((case.graph.obligations[0].obligation_id,), report.missing_obligation_ids)

    def test_verifier_source_has_no_paegen_or_oracle_import(self) -> None:
        forbidden = {"paegen", "htgl_dataset_generator", "oracle"}
        for directory in ("evidence", "proof", "erasure", "analytics"):
            for path in (PROJECT_ROOT / "src" / directory).glob("*.py"):
                imported = set()
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if isinstance(node, ast.Import):
                        imported.update(alias.name.split(".")[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module.split(".")[0])
                self.assertFalse(imported & forbidden, path)


class PBFTBackendTests(unittest.TestCase):
    class Client:
        certificate = None

        def validate_receipt(self, receipt, obligation, evaluation_time):
            del receipt, obligation, evaluation_time
            return self.certificate

    def test_pbft_backend_enforces_model_assumptions_quorum_and_commitment(self) -> None:
        row = obligation(1)
        evidence = receipt(row, "PBFT-R")
        client = self.Client()
        backend = PBFTValidationBackend(client, validator_count=4, fault_tolerance=1)
        client.certificate = PBFTValidationCertificate(
            receipt_commitment=backend.receipt_commitment(evidence),
            validator_ids=("V1", "V2", "V3", "V4"), approving_validator_ids=("V1", "V2", "V3"),
            authenticator_valid=True, credential_valid_at_event=True,
            anchor_valid=True, ordering_support_valid=True,
        )
        accepted = backend.validate(evidence, row, EVALUATION)
        self.assertTrue(accepted.verification_material_available)
        weak = PBFTValidationBackend(client, validator_count=3, fault_tolerance=1)
        rejected = weak.validate(evidence, row, EVALUATION)
        self.assertFalse(rejected.assumptions_valid)
        self.assertIn("PBFT_N_LT_3F_PLUS_1", rejected.diagnostics)


if __name__ == "__main__":
    unittest.main()
