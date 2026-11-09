from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import (  # noqa: E402
    CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES,
    CONTROLLED_SYNTHETIC_SOURCE_PREFIX,
    CORE_VALIDATION_CHECK_IDS,
    ConfigResolutionError,
    build_run_plan,
    load_config,
    resolve_config,
    resolve_config_file,
)


class ConfigResolverTests(unittest.TestCase):
    def test_sample_configs_resolve(self) -> None:
        for name in ("reference_10k.json", "small_deterministic.json", "represented_450m.json"):
            resolved = resolve_config_file(REPO_ROOT / "configs" / name)
            self.assertRegex(resolved.config_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(
                resolved.output.schema_contract_fingerprint,
                resolved.resolved_references["schema_contract_fingerprint"],
            )
            self.assertEqual("1.1.0", resolved.run.contract_version)
            self.assertIn(
                resolved.physical.backend, CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES
            )
            self.assertTrue(resolved.physical.is_controlled_synthetic)
            self.assertTrue(
                all(
                    source_id.startswith(CONTROLLED_SYNTHETIC_SOURCE_PREFIX)
                    for source_id in resolved.physical.calibration_source_ids
                )
            )
            self.assertTrue(
                all(
                    resolved.source_labels[path] == "controlled_synthetic"
                    for path in resolved.source_labels
                    if path.startswith("/physical/")
                )
            )

    def test_digest_is_stable_across_runs_and_key_order(self) -> None:
        raw = dict(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        first = resolve_config(raw)
        second = resolve_config(copy.deepcopy(raw))
        reordered = {key: raw[key] for key in reversed(list(raw.keys()))}
        third = resolve_config(reordered)
        self.assertEqual(first.config_sha256, second.config_sha256)
        self.assertEqual(first.config_sha256, third.config_sha256)

    def test_digest_excludes_nonsemantic_source_path(self) -> None:
        source = REPO_ROOT / "configs" / "small_deterministic.json"
        expected = resolve_config_file(source).config_sha256
        self.assertEqual(expected, resolve_config_file(str(source)).config_sha256)
        self.assertEqual(
            expected,
            resolve_config_file(Path(os.path.relpath(source, Path.cwd()))).config_sha256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "renamed-config.json"
            shutil.copyfile(source, copied)
            copied_resolved = resolve_config_file(copied)
            source_resolved = resolve_config_file(source)
            self.assertEqual(expected, copied_resolved.config_sha256)
            self.assertEqual(source_resolved.as_dict(), copied_resolved.as_dict())
            self.assertNotEqual(source_resolved.source_path, copied_resolved.source_path)

    def test_missing_source_label_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["run"]["contract_version"] = "1.0.0"
        with self.assertRaisesRegex(ConfigResolutionError, "source-labelled"):
            resolve_config(raw)

    def test_unknown_enum_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["physical"]["backend"]["value"] = "made_up_backend"
        with self.assertRaisesRegex(
            ConfigResolutionError, "unsupported physical profile"
        ):
            resolve_config(raw)

    def test_deferred_external_physical_backend_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["physical"]["backend"]["value"] = "opensynth_faraday"
        with self.assertRaisesRegex(
            ConfigResolutionError, "external integration.*deferred"
        ):
            resolve_config(raw)

    def test_real_physical_source_id_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["physical"]["calibration_source_ids"]["value"] = ["SRC-LCL-SCHEMA"]
        with self.assertRaisesRegex(ConfigResolutionError, "real or external source IDs"):
            resolve_config(raw)

    def test_controlled_physical_profile_rejects_calibrated_source_label(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["physical"]["calibration_bundle_id"]["source"] = "calibrated_from_source"
        with self.assertRaisesRegex(
            ConfigResolutionError, "requires source=controlled_synthetic"
        ):
            resolve_config(raw)

    def test_controlled_physical_profile_rejects_external_solver_identity(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["physical"]["solver_backend"]["value"] = "opendss.v9"
        with self.assertRaisesRegex(ConfigResolutionError, "external solver execution is deferred"):
            resolve_config(raw)

    def test_negative_rate_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["arrivals"]["base_rates_per_day"]["value"]["consent"] = -0.1
        with self.assertRaisesRegex(ConfigResolutionError, "negative numeric value"):
            resolve_config(raw)

    def test_unpinned_version_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["run"]["code_version"]["value"] = "latest"
        with self.assertRaisesRegex(ConfigResolutionError, "unpinned"):
            resolve_config(raw)

    def test_ambiguous_timestamp_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["run"]["horizon_start"]["value"] = "2026-01-01T00:00:00"
        with self.assertRaisesRegex(ConfigResolutionError, "timestamp must include Z or offset"):
            resolve_config(raw)

    def test_missing_group_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw.pop("sampling")
        with self.assertRaisesRegex(ConfigResolutionError, "missing groups"):
            resolve_config(raw)

    def test_450m_config_keeps_n_n_q_separate(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        self.assertEqual(450000000, resolved.claim_scale.represented_population)
        self.assertEqual(100000, resolved.claim_scale.materialized_row_target)
        self.assertIsNone(resolved.claim_scale.executed_operation_target)
        self.assertFalse(resolved.claim_scale.operational_claim_allowed)
        self.assertTrue(resolved.claim_scale.scale_claim_allowed)
        self.assertEqual(30, len(build_run_plan(resolved)))

    def test_operational_claim_requires_q(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["claim_scale"]["operational_claim_allowed"]["value"] = True
        raw["claim_scale"]["executed_operation_target"]["value"] = None
        with self.assertRaisesRegex(ConfigResolutionError, "operational claims require"):
            resolve_config(raw)

    def test_bare_jsonl_adapter_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["output"]["adapters"]["value"] = ["jsonl", "xes", "jsonld"]
        with self.assertRaisesRegex(ConfigResolutionError, "bare jsonl is ambiguous"):
            resolve_config(raw)

    def test_unknown_interoperability_adapter_fails_before_generation(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["output"]["adapters"]["value"] = ["unknown_projection"]
        with self.assertRaisesRegex(ConfigResolutionError, "unknown interoperability adapters"):
            resolve_config(raw)

    def test_evidence_adversarial_weights_must_be_complete_and_normalized(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["evidence"]["adversarial_case_weights"]["value"].pop("malformed")
        with self.assertRaisesRegex(ConfigResolutionError, "seven controlled fixture cases"):
            resolve_config(raw)
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["evidence"]["adversarial_case_weights"]["value"]["invalid"] = 0.5
        with self.assertRaisesRegex(ConfigResolutionError, "weights must sum to 1"):
            resolve_config(raw)

    def test_ml_removal_requires_a_separately_pinned_input_contract(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw["evidence"]["ml_removal_profile_ids"]["value"] = ["UNPINNED-REMOVAL"]
        with self.assertRaisesRegex(ConfigResolutionError, "model-removal evidence requires"):
            resolve_config(raw)

    def test_sampling_contract_rejects_unknown_design_and_unbound_strata(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["sampling"]["design_types"]["value"] = ["first_n"]
        with self.assertRaisesRegex(ConfigResolutionError, "unknown enum"):
            resolve_config(raw)

        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["sampling"]["strata_definitions"]["value"] = [
            "workflow=region_id:event_family"
        ]
        with self.assertRaisesRegex(ConfigResolutionError, "every and only"):
            resolve_config(raw)

    def test_sampling_contract_requires_real_simulation_thresholds(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["sampling"]["simulation_repetitions"]["value"] = 10
        with self.assertRaisesRegex(ConfigResolutionError, "at least 100"):
            resolve_config(raw)

        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["sampling"]["minimum_ci_coverage"]["value"] = 0.99
        with self.assertRaisesRegex(ConfigResolutionError, "no greater"):
            resolve_config(raw)

    def test_validation_profile_is_additive_and_cannot_remove_core_checks(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["validation"]["required_check_ids"]["value"] = ["SCHEMA-001"]
        resolved = resolve_config(raw)
        self.assertEqual(
            set(CORE_VALIDATION_CHECK_IDS),
            set(resolved.validation.required_check_ids),
        )

    def test_validation_profile_rejects_duplicate_and_malformed_check_ids(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["validation"]["required_check_ids"]["value"] = ["SCHEMA-001", "SCHEMA-001"]
        with self.assertRaisesRegex(ConfigResolutionError, "duplicate check IDs"):
            resolve_config(raw)

        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["validation"]["required_check_ids"]["value"] = ["not stable"]
        with self.assertRaisesRegex(ConfigResolutionError, "malformed IDs"):
            resolve_config(raw)


if __name__ == "__main__":
    unittest.main()
