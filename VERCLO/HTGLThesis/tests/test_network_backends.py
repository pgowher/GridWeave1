from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation import (
    ExtensionStudyConfig,
    NetworkStudyConfig,
    run_local_extension_study,
    run_network_backend_study,
)
from evaluation.network_study import EVALUATION_TIME, VALIDATORS, _fixture
from evidence import BackendValidation
from proof import (
    NetworkFaultProfile,
    NetworkMerkleValidationBackend,
    NetworkPBFTCluster,
    NetworkSignedValidationBackend,
    PBFTValidationBackend,
    serve_merkle_authority,
    serve_signed_authority,
)


class NetworkBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt, self.obligation = _fixture()
        self.decision = BackendValidation(
            "validator", anchor_valid=True, ordering_support_valid=True
        )

    def test_network_backends_are_substitutable_at_validation_interface(self) -> None:
        signed_service, signed_key = serve_signed_authority("AUTHORITY", self.decision)
        with signed_service:
            signed = NetworkSignedValidationBackend(
                signed_service.url, "AUTHORITY", signed_key
            )
            signed_result = signed.validate(
                self.receipt, self.obligation, EVALUATION_TIME
            )
        merkle_service, merkle_key = serve_merkle_authority("MERKLE", self.decision)
        with merkle_service:
            merkle = NetworkMerkleValidationBackend(
                merkle_service.url, "MERKLE", merkle_key
            )
            merkle_result = merkle.validate(
                self.receipt, self.obligation, EVALUATION_TIME
            )
        with NetworkPBFTCluster(VALIDATORS, self.decision) as cluster:
            pbft_result = cluster.backend().validate(
                self.receipt, self.obligation, EVALUATION_TIME
            )
        self.assertTrue(signed_result.verification_material_available)
        self.assertTrue(merkle_result.verification_material_available)
        self.assertTrue(pbft_result.verification_material_available)
        for result in (signed_result, merkle_result, pbft_result):
            self.assertTrue(result.authenticator_valid)
            self.assertTrue(result.anchor_valid)
            self.assertTrue(result.ordering_support_valid)

    def test_pbft_tolerates_one_partition_or_byzantine_but_not_two(self) -> None:
        profiles = (
            (NetworkFaultProfile(partitioned_validator_ids=("VALIDATOR-4",)), True),
            (
                NetworkFaultProfile(
                    partitioned_validator_ids=("VALIDATOR-3", "VALIDATOR-4")
                ),
                False,
            ),
            (NetworkFaultProfile(equivocating_validator_ids=("VALIDATOR-4",)), True),
            (
                NetworkFaultProfile(
                    equivocating_validator_ids=("VALIDATOR-3", "VALIDATOR-4")
                ),
                False,
            ),
        )
        for profile, expected in profiles:
            with self.subTest(profile=profile):
                with NetworkPBFTCluster(
                    VALIDATORS, self.decision, fault_profile=profile
                ) as cluster:
                    result = cluster.backend().validate(
                        self.receipt, self.obligation, EVALUATION_TIME
                    )
                self.assertEqual(expected, result.verification_material_available)

    def test_pbft_adapter_rejects_tampered_commit_vote(self) -> None:
        with NetworkPBFTCluster(VALIDATORS, self.decision) as cluster:
            client = cluster.client()
            certificate = client.validate_receipt(
                self.receipt, self.obligation, EVALUATION_TIME
            )
            votes = list(certificate.signed_commit_votes)
            votes[0] = replace(votes[0], signature="A" * 86)
            tampered = replace(certificate, signed_commit_votes=tuple(votes))

            class StaticClient:
                def validate_receipt(self, receipt, obligation, evaluation_time):
                    del receipt, obligation, evaluation_time
                    return tampered

            backend = PBFTValidationBackend(
                StaticClient(),
                4,
                1,
                validator_public_keys=client.public_keys,
                membership_epoch=cluster.membership_epoch,
                require_signed_votes=True,
            )
            result = backend.validate(self.receipt, self.obligation, EVALUATION_TIME)
        self.assertFalse(result.verification_material_available)
        self.assertIn("PBFT_VOTE_SIGNATURE_INVALID", result.diagnostics)

    def test_registered_network_study_executes_cost_and_fault_cells(self) -> None:
        report = run_network_backend_study(
            NetworkStudyConfig(repetitions=3, warmups=0)
        )
        self.assertEqual(4, len(report["backends"]))
        self.assertEqual(11, len(report["fault_cases"]))
        self.assertTrue(all(row["correct"] for row in report["fault_cases"]))
        self.assertTrue(all(row["success_rate"] == 1.0 for row in report["backends"]))
        pbft = next(
            row for row in report["backends"] if row["backend"] == "network-pbft-4f1-v2"
        )
        self.assertEqual(13, pbft["messages_median"])
        self.assertEqual(64, len(report["study_sha256"]))

    def test_authenticated_view_change_replaces_crashed_leader(self) -> None:
        profile = NetworkFaultProfile(crashed_validator_ids=("VALIDATOR-1",))
        with NetworkPBFTCluster(
            VALIDATORS, self.decision, fault_profile=profile
        ) as cluster:
            backend = cluster.backend()
            result = backend.validate(
                self.receipt, self.obligation, EVALUATION_TIME
            )
            cost = dict(backend.client.last_cost)
        self.assertTrue(result.verification_material_available)
        self.assertEqual(1, cost["view"])
        self.assertGreaterEqual(cost["view_change_votes"], 3)
        self.assertEqual(3, cost["commit_votes"])

    def test_durable_restart_preserves_sequence_and_replica_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verclo-pbft-state-") as state:
            with NetworkPBFTCluster(
                VALIDATORS, self.decision, persistent_root=state
            ) as cluster:
                first_backend = cluster.backend()
                first = first_backend.validate(
                    self.receipt, self.obligation, EVALUATION_TIME
                )
                first_sequence = first_backend.client.last_cost["sequence"]
            with NetworkPBFTCluster(
                VALIDATORS, self.decision, persistent_root=state
            ) as restarted:
                second_backend = restarted.backend()
                second = second_backend.validate(
                    replace(self.receipt, receipt_id="P13:RECEIPT:RESTART"),
                    self.obligation,
                    EVALUATION_TIME,
                )
                summaries = [
                    service._server.service.state.summary()  # type: ignore[attr-defined]
                    for service in restarted.services.values()
                ]
            self.assertTrue(first.verification_material_available)
            self.assertTrue(second.verification_material_available)
            self.assertEqual(1, first_sequence)
            self.assertEqual(2, second_backend.client.last_cost["sequence"])
            self.assertTrue(all(row["committed"] >= 2 for row in summaries))

    def test_concurrent_requests_and_larger_committees(self) -> None:
        for size in (4, 7, 10):
            validator_ids = tuple(f"VALIDATOR-{index:02d}" for index in range(1, size + 1))
            with self.subTest(size=size):
                with NetworkPBFTCluster(validator_ids, self.decision) as cluster:
                    backend = cluster.backend(timeout=2.0)

                    def validate(index: int):
                        return backend.validate(
                            replace(self.receipt, receipt_id=f"P13:CONCURRENT:{size}:{index}"),
                            self.obligation,
                            EVALUATION_TIME,
                        )

                    with ThreadPoolExecutor(max_workers=4) as executor:
                        results = list(executor.map(validate, range(8)))
                self.assertTrue(
                    all(result.verification_material_available for result in results)
                )

    def test_tpds_extension_study_covers_all_local_dimensions(self) -> None:
        report = run_local_extension_study(
            ExtensionStudyConfig(
                concurrency_levels=(1, 2),
                operations_per_level=4,
                committee_sizes=(4, 7),
            )
        )
        self.assertTrue(report["authenticated_view_change"]["accepted"])
        self.assertTrue(report["durable_recovery"]["accepted_after_restart"])
        self.assertEqual([4, 7], [row["committee_size"] for row in report["committee_results"]])
        self.assertTrue(all(row["success_rate"] == 1.0 for row in report["load_results"]))
        self.assertEqual(64, len(report["study_sha256"]))


if __name__ == "__main__":
    unittest.main()
