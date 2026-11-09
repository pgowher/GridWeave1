from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.api import (  # noqa: E402
    compile_artifact_release,
    export_adapter,
    report_claims,
    reproduce_release,
)
from htgl_dataset_generator.artifacts import RELEASE_EVIDENCE_PATH  # noqa: E402


class CliPublicationWorkflowIntegrationTests(unittest.TestCase):
    def test_publication_claim_adapter_and_reproduction_workflow(self) -> None:
        config = REPO_ROOT / "configs" / "small_deterministic.json"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiled = compile_artifact_release(
                config,
                root,
                publication=True,
                worker_count=1,
            )
            self.assertTrue(compiled.publication_eligible)
            restricted_root = compiled.release.bundle("restricted").release_root
            self.assertTrue(
                (restricted_root / RELEASE_EVIDENCE_PATH).is_file()
            )
            evidence = json.loads(
                (restricted_root / RELEASE_EVIDENCE_PATH).read_text(
                    encoding="utf-8"
                )
            )
            stage_rows = evidence["performance_by_run"][0]["value"]["stage_observations"]
            self.assertEqual(14, len(stage_rows))
            self.assertTrue(all(row["table_record_digests"] for row in stage_rows))
            self.assertTrue(all(row["artifact_sha256"] for row in stage_rows))
            self.assertTrue(all(row["row_group_count"] > 0 for row in stage_rows))

            claims = report_claims(
                config,
                compiled.release.release_root,
                root,
            )
            self.assertGreater(claims.claim_count, 0)
            self.assertEqual(
                claims.claim_count,
                len(claims.supported_claim_ids) + len(claims.unsupported_claim_ids),
            )

            adapter = export_adapter(
                config,
                compiled.release.release_root,
                root,
                adapter_id="csv",
            )
            self.assertGreater(adapter.exported_file_count, 5)
            self.assertTrue(
                (adapter.export_root / "adapter" / "loss_report.json").is_file()
            )
            self.assertTrue(
                (
                    adapter.export_root
                    / "adapter"
                    / "mapping"
                    / "field_mapping.parquet"
                ).is_file()
            )

            reproduced = reproduce_release(
                config,
                compiled.release.release_root,
                root,
                worker_count=1,
            )
            self.assertTrue(reproduced.semantic_digest_match)
            self.assertTrue(reproduced.byte_digest_match)
            self.assertTrue(reproduced.manifest_sha256_match)


if __name__ == "__main__":
    unittest.main()
