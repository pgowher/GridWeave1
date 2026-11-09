from __future__ import annotations

import copy
from dataclasses import fields, replace
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import load_config, resolve_config  # noqa: E402
from htgl_dataset_generator.evidence import (  # noqa: E402
    ReceiptPayloadFacts,
    ReceiptProfileError,
    SyntheticKeyFixture,
    canonical_receipt_payload,
    load_receipt_profile_bundle,
    verify_evidence_receipts,
)
from htgl_dataset_generator.evidence.crypto import (  # noqa: E402
    authenticate,
    derive_synthetic_key,
    verify_authenticator,
)
from htgl_dataset_generator.evidence.fixtures import MerkleProofStep  # noqa: E402
from htgl_dataset_generator.evidence.merkle import build_merkle_anchor, verify_merkle_path  # noqa: E402
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_evidence  # noqa: E402
from htgl_dataset_generator.io import write_evidence_fixture_bundle, write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import CounterRng, canonical_records_digest  # noqa: E402


class EvidenceReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.base_raw = load_config(REPO_ROOT / "configs" / "small_deterministic.json")
        cls.default_resolved = resolve_config(copy.deepcopy(cls.base_raw))
        cls.default_result = orchestrate_pipeline_through_evidence(cls.default_resolved)[0]

        honest_raw = copy.deepcopy(cls.base_raw)
        honest_raw["evidence"]["honest_rate"]["value"] = 1.0
        honest_raw["evidence"]["adversarial_rate"]["value"] = 0.0
        cls.honest_resolved = resolve_config(honest_raw)
        cls.honest_result = orchestrate_pipeline_through_evidence(cls.honest_resolved)[0]

        adversarial_raw = copy.deepcopy(cls.base_raw)
        adversarial_raw["evidence"]["honest_rate"]["value"] = 0.0
        adversarial_raw["evidence"]["adversarial_rate"]["value"] = 1.0
        cls.adversarial_resolved = resolve_config(adversarial_raw)
        cls.adversarial_result = orchestrate_pipeline_through_evidence(cls.adversarial_resolved)[0]

    @staticmethod
    def _parts(result):
        receipt_build = result.artifacts.evidence_receipts
        through_obligations = result.artifacts.through_obligations
        through_policy = through_obligations.through_policy
        through_dag = through_policy.through_dag
        return receipt_build, through_obligations.evidence_obligations, through_dag

    def test_profile_bundle_is_pinned_complete_and_disables_uncontracted_ml_removal(self) -> None:
        bundle = load_receipt_profile_bundle(self.default_resolved, contract=self.contract)
        self.assertEqual(self.default_resolved.evidence.receipt_profile_bundle_sha256, bundle.bundle_sha256)
        self.assertEqual(set(self.contract.dictionary_values("evidence_type")), {item.evidence_type for item in bundle.profiles})
        self.assertEqual({"digest", "hmac", "signature", "merkle_inclusion"}, {item.primitive for item in bundle.profiles})
        self.assertEqual((), bundle.ml_removal_profiles)
        self.assertIn("do not prove physical deletion", bundle.proof_limit_statement)

    def test_honest_receipts_recompute_valid_and_all_obligations_are_sufficient(self) -> None:
        build, obligations, _ = self._parts(self.honest_result)
        self.assertEqual(len(obligations.evidence_obligations), len(build.evidence_receipts))
        self.assertEqual(len(build.evidence_receipts), build.verification.diagnostics.valid_count)
        self.assertEqual(0, build.verification.diagnostics.truth_mismatch_count)
        self.assertTrue(all(item.truth_matches_declared for item in build.verification.truth))
        self.assertTrue(all(item.sufficient for item in build.verification.sufficiency.truth))
        self.assertFalse(build.adversarial_cases)

    def test_conditioned_adversarial_generation_exercises_every_required_case(self) -> None:
        build, _, _ = self._parts(self.adversarial_result)
        case_types = {item.case_type for item in build.adversarial_cases}
        self.assertEqual(
            {
                "invalid",
                "late",
                "malformed",
                "contradictory",
                "forged_under_synthetic_key",
                "incomplete",
                "missing_dependency",
            },
            case_types,
        )
        self.assertGreater(build.verification.diagnostics.invalid_count, 0)
        self.assertGreater(build.verification.diagnostics.expired_count, 0)
        self.assertGreater(build.verification.diagnostics.missing_dependency_count, 0)
        self.assertGreater(build.verification.diagnostics.contradiction_count, 0)
        self.assertEqual(0, build.verification.diagnostics.truth_mismatch_count)
        omitted = [item for item in build.adversarial_cases if item.case_type == "incomplete"]
        self.assertTrue(omitted)
        self.assertTrue(all(not item.receipt_ids and item.omission_reason for item in omitted))
        forged_ids = {
            receipt_id
            for item in build.adversarial_cases
            if item.case_type == "forged_under_synthetic_key"
            for receipt_id in item.receipt_ids
        }
        fixtures = {item.receipt_id: item for item in build.receipt_fixtures}
        self.assertTrue(all(fixtures[item].claimed_key_id != fixtures[item].actual_key_id for item in forged_ids))
        self.assertTrue(all(not item.sufficient for item in build.verification.sufficiency.truth))

    def test_default_rate_is_conditioned_over_real_coverage_units(self) -> None:
        build, _, _ = self._parts(self.default_result)
        diagnostic = build.diagnostics[self.default_resolved.run.scenario_id]
        expected = int(diagnostic.coverage_unit_count * self.default_resolved.evidence.adversarial_rate + 0.5)
        self.assertEqual(expected, diagnostic.adversarial_unit_count)
        self.assertEqual(diagnostic.coverage_unit_count - expected, diagnostic.honest_unit_count)
        self.assertEqual(diagnostic.coverage_unit_count, diagnostic.honest_unit_count + diagnostic.adversarial_unit_count)

    def test_canonical_serialization_normalizes_time_and_rejects_cross_domain_substitution(self) -> None:
        bundle = load_receipt_profile_bundle(self.honest_resolved, contract=self.contract)
        profile = bundle.profile("digest")
        facts = ReceiptPayloadFacts(
            receipt_id="R-1",
            obligation_id="O-1",
            evidenced_event_id="E-1",
            triggering_event_id="E-1",
            policy_rule_id="P-1",
            subject_object_id="OBJ-1",
            responsible_actor_id="A-1",
            issuer_actor_id="A-1",
            evidence_type="digest",
            issued_at="2026-01-01T00:00:00Z",
            due_at="2026-01-01T01:00:00+00:00",
            coverage_scope="object",
            covers_replica_ids=(),
        )
        first = canonical_receipt_payload(facts, profile=profile, bundle=bundle, contract=self.contract)
        second = canonical_receipt_payload(
            replace(facts, issued_at="2026-01-01T00:00:00.000000+00:00", due_at="2026-01-01T01:00:00.000000Z"),
            profile=profile,
            bundle=bundle,
            contract=self.contract,
        )
        self.assertEqual(first, second)
        substituted = first.replace(profile.domain.encode(), ("x" + profile.domain[1:]).encode(), 1)
        self.assertNotEqual(hashlib.sha256(first).digest(), hashlib.sha256(substituted).digest())

    def test_independent_verifier_detects_bit_mutation_and_domain_substitution(self) -> None:
        build, obligations, through_dag = self._parts(self.honest_result)
        fixture = build.receipt_fixtures[0]
        authenticator = bytes.fromhex(fixture.authenticator_hex)
        mutated_auth = (bytes([authenticator[0] ^ 1]) + authenticator[1:]).hex()
        fixtures = tuple(
            replace(item, authenticator_hex=mutated_auth) if item.receipt_id == fixture.receipt_id else item
            for item in build.receipt_fixtures
        )
        result = verify_evidence_receipts(
            self.honest_resolved,
            build.evidence_receipts,
            fixtures,
            build.synthetic_keys,
            build.synthetic_anchors,
            obligations,
            world=through_dag.world,
            catalog=through_dag.catalog,
            causal_dag=through_dag.causal_dag,
            replicate_id=0,
            require_truth_match=False,
        )
        truth = next(item for item in result.truth if item.receipt_id == fixture.receipt_id)
        self.assertFalse(truth.authenticator_valid)
        self.assertEqual("invalid", truth.expected_status)
        self.assertFalse(truth.truth_matches_declared)

        payload = bytes.fromhex(fixture.canonical_payload_hex)
        domain_mutation = payload.replace(b"htgl/evidence/receipt/", b"xtgl/evidence/receipt/", 1).hex()
        fixtures = tuple(
            replace(item, canonical_payload_hex=domain_mutation) if item.receipt_id == fixture.receipt_id else item
            for item in build.receipt_fixtures
        )
        result = verify_evidence_receipts(
            self.honest_resolved,
            build.evidence_receipts,
            fixtures,
            build.synthetic_keys,
            build.synthetic_anchors,
            obligations,
            world=through_dag.world,
            catalog=through_dag.catalog,
            causal_dag=through_dag.causal_dag,
            replicate_id=0,
            require_truth_match=False,
        )
        truth = next(item for item in result.truth if item.receipt_id == fixture.receipt_id)
        self.assertFalse(truth.canonical_payload_valid)
        self.assertEqual("invalid", truth.expected_status)

    def test_all_crypto_primitives_and_merkle_mutation_detection(self) -> None:
        bundle = load_receipt_profile_bundle(self.honest_resolved, contract=self.contract)
        rng = CounterRng("1" * 64)
        payload = b"canonical-test-payload"
        for profile in bundle.profiles:
            key = None
            if profile.requires_key:
                key = derive_synthetic_key(
                    rng,
                    subject_actor_id="ACTOR-TEST",
                    primitive=profile.primitive,
                    algorithm=profile.algorithm,
                )
            authenticator = authenticate(profile, payload, key)
            self.assertTrue(verify_authenticator(profile, payload, authenticator, key), profile.evidence_type)
            mutated = bytes([authenticator[0] ^ 1]) + authenticator[1:]
            self.assertFalse(verify_authenticator(profile, payload, mutated, key), profile.evidence_type)

        anchor_profile = bundle.anchor_profiles[0]
        leaves = {"r1": "1" * 64, "r2": "2" * 64, "r3": "3" * 64}
        anchor, paths = build_merkle_anchor(leaves, profile=anchor_profile, scenario_id="S", replicate_id=0)
        self.assertTrue(verify_merkle_path(leaves["r3"], paths["r3"], root_digest=anchor.root_digest, profile=anchor_profile))
        mutated_path = list(paths["r3"])
        mutated_path[0] = MerkleProofStep("0" * 64, mutated_path[0].sibling_position)
        self.assertFalse(verify_merkle_path(leaves["r3"], mutated_path, root_digest=anchor.root_digest, profile=anchor_profile))

    def test_released_key_fixtures_contain_no_secret_material(self) -> None:
        build, _, _ = self._parts(self.honest_result)
        field_names = {item.name for item in fields(SyntheticKeyFixture)}
        self.assertNotIn("secret", field_names)
        self.assertNotIn("private_key", field_names)
        self.assertTrue(build.synthetic_keys)
        self.assertTrue(all(len(item.secret_material_sha256) == 64 for item in build.synthetic_keys))

    def test_receipts_are_schema_valid_and_write_zstd_parquet(self) -> None:
        import pyarrow.parquet as pq

        build, _, _ = self._parts(self.default_result)
        for row in build.evidence_receipts:
            validate_record(self.contract, "evidence_receipt", row)
        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(build.table_records(), Path(tmp), contract=self.contract)
            table = pq.read_table(written["evidence_receipt"])
            self.assertEqual(len(build.evidence_receipts), table.num_rows)
            self.assertEqual(b"htgl.dataset.v1.evidence_receipt", table.schema.metadata[b"schema_id"])
            self.assertEqual(
                "ZSTD",
                pq.ParquetFile(written["evidence_receipt"]).metadata.row_group(0).column(0).compression,
            )

    def test_detached_fixture_bundle_is_atomic_deterministic_and_evaluator_only(self) -> None:
        build, _, _ = self._parts(self.default_result)
        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first = write_evidence_fixture_bundle(build, first_tmp)
            second = write_evidence_fixture_bundle(build, second_tmp)
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("evaluator_only", manifest["privacy_class"])
            self.assertFalse(manifest["authoritative_dataset_table"])
            self.assertIn("do not prove physical deletion", manifest["proof_limit_statement"])
            self.assertEqual(
                {path: hashlib.sha256(file.read_bytes()).hexdigest() for path, file in first.files.items()},
                {path: hashlib.sha256(file.read_bytes()).hexdigest() for path, file in second.files.items()},
            )
            for row in build.evidence_receipts:
                receipt_id = str(row["receipt_id"])
                self.assertTrue((first.root / "payloads" / f"{receipt_id}.bin").is_file())
            key_text = (first.root / "synthetic_keys.json").read_text(encoding="utf-8")
            self.assertNotIn('"private_key"', key_text)
            self.assertNotIn('"hmac_key"', key_text)

    def test_profile_digest_tampering_fails_closed(self) -> None:
        source = REPO_ROOT / "evidence" / "receipt_profiles_v1.json"
        raw = json.loads(source.read_text(encoding="utf-8"))
        raw["profiles"][0]["domain"] += "-tampered"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ReceiptProfileError, "SHA-256"):
                load_receipt_profile_bundle(self.default_resolved, path, contract=self.contract)

    def test_replicate_orchestration_is_worker_order_invariant(self) -> None:
        raw = copy.deepcopy(self.base_raw)
        raw["run"]["replicate_count"]["value"] = 2
        raw["validation"]["repetition_count"]["value"] = 2
        resolved = resolve_config(raw)
        serial = orchestrate_pipeline_through_evidence(resolved, worker_count=1)
        parallel = orchestrate_pipeline_through_evidence(resolved, worker_count=2)
        self.assertEqual([item.table_digests for item in serial], [item.table_digests for item in parallel])
        self.assertNotEqual(
            parallel[0].table_digests["evidence_receipt"],
            parallel[1].table_digests["evidence_receipt"],
        )
        self.assertEqual(
            canonical_records_digest(parallel[0].artifacts.evidence_receipts.evidence_receipts),
            parallel[0].table_digests["evidence_receipt"],
        )


if __name__ == "__main__":
    unittest.main()
