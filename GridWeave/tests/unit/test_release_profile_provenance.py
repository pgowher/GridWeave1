from __future__ import annotations

from dataclasses import replace
import unittest
from pathlib import Path

from htgl_dataset_generator.config import (
    PROCEDURAL_CONTROLLED_SYNTHETIC_V1,
    ReleaseProfileError,
    resolve_config_file,
    validate_resolved_release_profile,
)
from htgl_dataset_generator.provenance import (
    CONTROLLED_SYNTHETIC_LICENCE_STATUS,
    SourceRegistryError,
    build_source_registry,
    validate_source_registry,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class ReleaseProfileProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(
            REPO_ROOT / "configs" / "small_deterministic.json"
        )
        cls.profile = validate_resolved_release_profile(cls.resolved)

    def test_supported_profile_is_frozen_and_rejects_external_semantics(self) -> None:
        self.assertEqual(PROCEDURAL_CONTROLLED_SYNTHETIC_V1, self.profile.profile_id)
        self.assertEqual("procedural", self.profile.physical_backend)
        self.assertIn(
            "external physical-backend integration or conformance",
            self.profile.prohibited_claims,
        )
        invalid_physical = replace(
            self.resolved.physical,
            backend="opensynth_style_synthetic",
        )
        with self.assertRaisesRegex(ReleaseProfileError, "style or external modes"):
            validate_resolved_release_profile(
                replace(self.resolved, physical=invalid_physical)
            )

    def test_registry_is_deterministic_typed_and_covers_every_source_label(self) -> None:
        left = build_source_registry(self.resolved, self.profile)
        right = build_source_registry(self.resolved, self.profile)
        self.assertEqual(left.registry_sha256, right.registry_sha256)
        self.assertIn(
            "CONTROLLED-SYNTHETIC-CONFIG-v1",
            {record.source_id for record in left.records},
        )
        covered = {
            path
            for record in left.records
            for path in record.transformation.output_parameter_paths
        }
        self.assertEqual(set(self.resolved.source_labels), covered)
        for record in left.records:
            self.assertEqual("controlled_synthetic", record.source_label)
            self.assertEqual(
                CONTROLLED_SYNTHETIC_LICENCE_STATUS,
                record.licence.status,
            )
            self.assertIsNone(record.source_uri)
            self.assertIsNone(record.observed_date_range)
            self.assertFalse(record.synthetic_record_content_included)

    def test_registry_tampering_fails_closed(self) -> None:
        registry = build_source_registry(self.resolved, self.profile)
        tampered_record = replace(
            registry.records[0],
            source_label="calibrated_from_source",
        )
        tampered = replace(
            registry,
            records=(tampered_record, *registry.records[1:]),
        )
        with self.assertRaisesRegex(SourceRegistryError, "external source label"):
            validate_source_registry(
                tampered,
                resolved=self.resolved,
                profile=self.profile,
            )


if __name__ == "__main__":
    unittest.main()
