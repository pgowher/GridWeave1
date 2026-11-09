# GridWeave schema and contract index

GridWeave 0.2.0 contains several versioned interfaces. They serve different consumers and must not be mixed merely because all represent synthetic erasure metadata.

| Interface | Authoritative location | Consumer |
|---|---|---|
| Retained table contract | `htgl_contract_v1.json` and `arrow/` in this directory | Raw/world Parquet generator and validators |
| Formal shared and worked-case records | `pae-common-v1`, `pae-ground-truth-v1`, `pae-observable-view-v1`, `pae-closure-worked-case-v1` JSON schemas | Model fixtures and formal validation |
| PaEGen v1 bundles | `paegen-ground-truth-bundle-v1`, `paegen-observer-bundle-v1`, `paegen-scenario-manifest-v1` | Privileged evaluator and sanitized v1 observer export |
| Smart-grid and attack profiles | `paegen-smart-grid-scenario-v1`, `paegen-attack-fixtures-v1`, `paegen-adversarial-receipts-v1`, `paegen-privacy-projections-v1` | Profile and controlled-fixture compilers |
| PaEBench working study | `paebench-study-contract-v1` and versioned `paebench-*-v1_1` / `v1_2` | Version-specific task corpora and study plans |
| Native three-file pipeline exchange | [PaEForge schemas](../../PaEForge/schemas) and [contract reader/writer](../../PaEForge/src/paeforge_contract) | Current native VERCLO pipeline |
| Native policy | [VERCLO policy directory](../../HTGLThesis/src/policy) | Policy registry and digest binding |
| Native synthetic E2 trust context | `CONTEXT_SCHEMA` in [gridweave_backend.py](../../PaEForge/src/paeforge_pipeline/gridweave_backend.py) | Registered public keys and signed exceptions |
| GridWeave dataset manifest and paired export | [dataset.py](../src/gridweave/dataset.py) executable validation rules | Dataset orchestrator/evaluator, with public subset sent to worker |

Names in the table omit `.schema.json` where repeated. JSON Schema files use their declared drafts; local `https://pae.local/schema/...` identifiers are registered locally rather than fetched as network resources.

## Oracle boundary

Ground truth, expected closure/categories, attack/operation labels, hidden topology, protected mappings and evaluator seeds remain sealed. A digest commitment does not authorize disclosure of its contents. Native VERCLO predictions are outputs; they must not be copied into the generator oracle as expected input. The native public tree is the handoff surface; version-specific formal ground-truth schemas are not worker inputs.

## Validation entry points

From the repository root with the environment activated, use `gridweave validate DATASET` for native exports, `python thesis.py study verify E1` for the retained v1.2 corpus, and `python Thesis_Docs-/Formal_Model/validate_phase_2_1.py` for the formal shared examples. Each check has its own scope; success does not convert one interface into another. Legacy `htgl_dataset_generator` imports are intentional. See the [dataset contract](../Docs/DATASET_CONTRACT_AND_DATA_CARD.md).
