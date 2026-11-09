# Paper: GridWeave: Weaving Custody, Obligations, and Evidence into Smart-Grid Benchmarks 

This bundle accompanies the current GridWeave benchmark paper. It includes the generator, GraphSpec and RelationalSpec, the VERCLO consumer, the inputs and evaluator labels used in the study, and the recorded evidence behind the paper.

## Datasets

| Resource | Units | Location |
| --- | ---: | --- |
| Reference corpus | 420 | [GridWeave/datasets/reference](GridWeave/datasets/reference/) |
| Structural extension | 120 | [research/GridWeave_Paper1/extension/corpus_v0_2](research/GridWeave_Paper1/extension/corpus_v0_2/) |
| Separately constructed fixtures | 98 | [research/GridWeave_Paper1/runs/paper1-study-v1/independent_fixtures](research/GridWeave_Paper1/runs/paper1-study-v1/independent_fixtures/) |

Each resource keeps its public assessor inputs and sealed evaluator expectations in separate directories. The two prototypes share the same bundled reference corpus. During the study, assessors receive public-only copies and the scoring step joins evaluator labels to saved predictions.

## Run the artifact

Run the commands from this folder. Use Bash and Python 3.11 or later. The setup scripts create the local environments required by the launchers. The generation profiling command requires a host with `wait4` support, such as Linux.

```sh
bash GridWeave/setup.sh
bash VERCLO/setup.sh
./research/GridWeave_Paper1/run-study test
```

Use a fresh output directory for each experiment. The full study runs the semantic comparisons, the seeded-fault utility experiment, and three recorded-source regenerations of each generated corpus.

```sh
./research/GridWeave_Paper1/run-study run --output /tmp/gridweave-paper1-new-study
```

The supplementary contract check has a separate entry point. It reads the bundled inputs and saves new predictions and comparisons outside the recorded runs.

```sh
./GridWeave/.venv/bin/python research/GridWeave_Paper1/scripts/verify_contract_corrections.py \
  --output /tmp/gridweave-paper1-new-contract-verification
```

See [Running the study](research/GridWeave_Paper1/RUNNING_THE_STUDY.md) and the [semantic specification](research/GridWeave_Paper1/SEMANTIC_SPECIFICATION.md) for component commands and scoring rules. Pass an absolute dataset path when invoking VERCLO directly. Keep any report regeneration in a separate output copy.

### Recompute the structural census

The census verifies the recorded source snapshot and recomputes distinct input counts, graph classes and custody distributions for each corpus.

```sh
lab=research/GridWeave_Paper1
python=./GridWeave/.venv/bin/python
"$python" "$lab/scripts/audit_reference.py" \
  --dataset GridWeave/datasets/reference --out /tmp/gridweave-reference-census
"$python" "$lab/scripts/audit_reference.py" \
  --dataset "$lab/extension/corpus_v0_2" --out /tmp/gridweave-extension-census
```

## Inspect the paper evidence

- The [historical study](research/GridWeave_Paper1/runs/paper1-study-v1/) contains the report, frozen predictions, scored comparisons, 9,600 raw mutant observations, and six generation measurements. The paper reports 1,276 GraphSpec and RelationalSpec comparisons for semantic validation and treats VERCLO’s 638 comparisons as consumer reuse. The archived report aggregates all 1,914 comparisons.
- The [development findings](research/GridWeave_Paper1/evidence/development_findings/) and [development run](research/GridWeave_Paper1/runs/development-study-1/) preserve the observed disagreements and resolutions, including the earlier fixture set, affected predictions and field-level witnesses.
- The [contract correction](research/GridWeave_Paper1/corrections/2026-11-08-contract-v1/) preserves the implementation diff, before and after source files, later verification, and recorded-source replay. Its verification is distinct from the historical study.
- [Manuscript evidence](manuscript-evidence/) retains the figure provenance and semantic coverage audit.

The bundled study datasets, evaluator labels, scored predictions, raw utility observations and historical generation measurements retain their original bytes. The reviewer copy uses one reference corpus and retains the development records relevant to the paper. The [anonymization record](ANONYMIZATION.md) documents the path redactions, refreshed checksums and bundle-specific runner changes. The artifact uses its local datasets and saved source snapshots for verification.

Verify the copied files before running any commands that write new outputs.

```sh
sha256sum --quiet -c SHA256SUMS
```

