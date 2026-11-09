from __future__ import annotations

from dataclasses import replace
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.artifacts import (  # noqa: E402
    ArtifactIntegrityError,
    DownstreamReplayObservation,
)
from htgl_dataset_generator.artifacts.reports import (  # noqa: E402
    build_claim_matrix,
    validate_downstream_replay_evidence,
    validate_publication_wording,
)
from htgl_dataset_generator.config import resolve_config_file  # noqa: E402


class PublicationReportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(
            REPO_ROOT / "configs" / "small_deterministic.json"
        )
        cls.key = (cls.resolved.run.scenario_id, 0)

    def test_forbidden_claim_wording_fails_closed(self) -> None:
        forbidden = (
            "HTGL handled 450 million users.",
            "900 million transactions executed.",
            "The receipt is proof of erasure.",
            "The release is GDPR compliant.",
            "This is a novel algorithm.",
        )
        for text in forbidden:
            with self.subTest(text=text):
                with self.assertRaises(ArtifactIntegrityError):
                    validate_publication_wording(text)

    def test_qualified_boundary_wording_is_allowed(self) -> None:
        validate_publication_wording(
            "The release represents N=450,000,000 and does not establish operational capacity."
        )

    def test_execution_target_never_becomes_observed_q(self) -> None:
        claim_scale = replace(
            self.resolved.claim_scale,
            executed_operation_target=10,
            operational_claim_allowed=True,
        )
        resolved = replace(self.resolved, claim_scale=claim_scale)
        guard = build_claim_matrix(
            resolved,
            {self.key: {"governance_event": ({"event_id": "E-1"},)}},
        )
        self.assertIsNone(guard["executed_operations"])
        self.assertFalse(guard["operational_execution_claim"])

    def test_measured_downstream_replay_is_digest_bound(self) -> None:
        claim_scale = replace(
            self.resolved.claim_scale,
            executed_operation_target=10,
            operational_claim_allowed=True,
        )
        resolved = replace(self.resolved, claim_scale=claim_scale)
        observation = DownstreamReplayObservation(
            run_id=resolved.run.run_id,
            scenario_id=self.key[0],
            replicate_id=self.key[1],
            executed_operation_count=10,
            implementation_id="HTGL-SIM-REFERENCE",
            implementation_version="1.0.0",
            software_profile_id="SOFTWARE-PINNED-v1",
            hardware_profile_id="HARDWARE-PINNED-v1",
            workload_sha256="1" * 64,
            result_sha256="2" * 64,
            throughput_operations_per_second=100.0,
            p50_latency_milliseconds=2.0,
            p95_latency_milliseconds=5.0,
            peak_resident_memory_bytes=1_000_000,
        )
        self.assertEqual(
            10,
            validate_downstream_replay_evidence(
                resolved,
                (self.key,),
                {self.key: observation},
            ),
        )
        malformed = replace(observation, result_sha256="not-a-digest")
        with self.assertRaisesRegex(ArtifactIntegrityError, "result_sha256"):
            validate_downstream_replay_evidence(
                resolved,
                (self.key,),
                {self.key: malformed},
            )


if __name__ == "__main__":
    unittest.main()
