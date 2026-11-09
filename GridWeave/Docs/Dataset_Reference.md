# GridWeave Dataset Reference

Implementation 0.2.1 exports format GridWeave-0.2.0 under the REAL_ED25519_SYNTHETIC_E2 profile. A dataset is the complete directory rooted at dataset-manifest.json. The supplied full standard dataset is datasets/reference relative to GridWeave.

| Artifact | Contents |
|---|---|
| dataset-manifest.json | Format, source identity, counts and complete file inventory |
| public/index.json | Unit IDs, split assignments and input/configuration file hashes |
| public/cases/UNIT/case-manifest.json | Native case identity, policy and input bindings |
| public/cases/UNIT/observer-projection.json | Allowed case, topology, policy, exceptions and challenge material |
| public/cases/UNIT/receipt-stream.json | Evidence assertions and stream commitment |
| public/configuration/UNIT/policies/policy.json | Policy for that unit |
| public/configuration/UNIT/verification-context.json | Synthetic public keys and signed exception context |
| sealed/cases/UNIT.json | Expected outcome, baseline state, obligation categories and latent-world facts |
| sealed/pairs.json | Complete pair membership, family, scale, operation, tags and byte cost |
| sealed/optimization.json | Coverage goals, selected witnesses and solver/comparison records |
| sealed/reproduction.json | Seed, source selection, scale factors and selection parameters |
| sealed/source and source-hashes.json | Actual source snapshot and hashes |

UNIT is an opaque 32-character hexadecimal ID. Every pair has two unique units. All descendants of a source family stay in one split within the dataset. Negative conditions are deliberate labelled cases.

Closure labels are CLOSED, CLOSED_WITH_EXCEPTIONS, PARTIALLY_CLOSED, OPEN, DISPUTED, UNVERIFIABLE and IN_PROGRESS. Obligation categories are COVERED, EXCEPTED, MISSING, INVALID, LATE and CONTRADICTORY. The Technical Guide defines their precedence and scope.

N_synthetic_source_families counts source templates; n_materialized_cases counts exported case units. q_status remains NOT_EXECUTED and q_executed_downstream_case_evaluations remains null during generation. READY_FOR_VERCLO_INPUT records successful dataset checks, not completed VERCLO evaluation.

The native exchange schemas are under support/PaEForge/schemas. The trust-context schema is CONTEXT_SCHEMA in support/PaEForge/src/paeforge_pipeline/gridweave_backend.py. Policy schemas and parsing are included under support/HTGLThesis. Dataset-level invariants are checked by src/gridweave/dataset.py.
