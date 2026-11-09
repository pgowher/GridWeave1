# Contract correction and separate verification

The active generator oracle and the two checkers' common public loader are corrected. The historical datasets, labels, predictions, mutant observations, development evidence, capsule, and generation measurements remain unchanged. This directory records the correction separately from `runs/paper1-study-v1`.

The corrected implementation is identified by `active_source_manifest.json`, the executable freeze in `verification/source-freeze.json`, the exact changes in `implementation.diff`, and the preserved `before/` and `after/` copies. The native format and original 98-fixture catalogue are unchanged. The changes do not assert independent human adjudication or broader policy support.

## Implementation changes

The oracle now requires `event_time <= submitted_at <= evaluation_time` and exactly one Ed25519 signature reference. The existing validity-start and optional expiry checks remain. This aligns the label-producing path with the stated receipt-admission rules and both new checkers.

The common loader now checks the profile identifier, version, and domain-separated digest in both manifest and observer policy references against the loaded policy. It rejects duplicate receipt identifiers before either new checker assesses a bundle. These envelope/profile checks are explicitly documented as a shared validation dependency; the graph and SQL assessment logic remains separate.

New generation-profiling executions capture CPU model, logical CPU count, physical memory, Python identity, and dependency versions in `host.json`. The capture identifies its execution time and is not used to backfill the historical host description. Historical corpus reproduction now materializes verified source snapshots saved with the corpora and records `RECORDED_GENERATION_SOURCE_REPLAY`. Preparing those snapshots is excluded from the timed generator-child interval. Normal GridWeave generation still uses the active corrected source and produces its own source identity.

## Verification results

The final correction verification is `verification/summary.json`. Earlier intermediate correction verification is retained separately; its repeated observations are not pooled into the following totals.

| Check | Result |
|---|---|
| Corrected oracle on all saved resources | 638 units; zero differences in the four scored fields |
| Previously discrepant existing submission fixtures | Both now match their declared expectations |
| Preserved generated-unit labels | 540 checked; zero changes |
| Corrected GraphSpec and RelationalSpec worker execution | 1,276 case comparisons; zero scored-field disagreements |
| Additional signature-cardinality probes | Zero references, two identical references, and two distinct references; nine assessments agree across oracle/GraphSpec/RelationalSpec |
| Additional malformed-envelope variants | Nine variants; both workers reject all nine before saving predictions: eighteen expected rejections |
| Paper-prototype tests | Thirteen tests passed; `tests.log` |
| Generator research-property/integration tests | Twenty-two tests passed; `generator_tests.log` |
| Native validation of preserved generated corpora | 420 reference and 120 extension units pass; original manifest hashes retained |
| Recorded-source replay | One additional replay per generated corpus; both manifests match exactly |
| Protected historical files | 10,924 checked; zero changed files or additions in the protected roots |

The 638 oracle checks and 1,276 new-worker comparisons are additional verification of existing units. They do not enlarge the paper's primary 638-unit resource or replace its historical 1,914 comparisons. The signature and malformed-input probes are additional targeted checks, not additions to the frozen 98-fixture resource. VERCLO was not rerun as part of the correction comparison; the generator integration tests exercise the existing consumer interface separately.

The extra replay observations in `recorded_source_replay/` are not pooled into the six historical generation observations and are not measurements of the active corrected generator's generation cost. The original medians and ranges remain identified with the original recorded source versions. The generator tests also check fresh corrected generation and same-source repeatability at their declared integration-test scale.

## Paper and documentation changes

The consolidated paper remains `${MANUSCRIPT_ROOT}/GridWeaveV2/main.tex`. It describes the code correction and separate verification; states that generated corpora have no `LATE` entries and all four such entries occur in boundary fixtures; names the seven authored source families and six native structural profiles; discloses shared envelope/profile validation; and limits the historical host description to recorded information. Saved category and case-support distributions are in the paper's `qa/semantic_coverage.json`.

Wording about nonblind implementation authoring, the initial semantic findings, construction baselines, map coverage, and the completed run identity is clarified. Verified bibliographic metadata is completed for ProvGen, Garg et al., and CAT without changing the eighteen citation keys. The original availability statement is preserved.

All ten original figure PDFs remain byte-identical. Their proportional display widths are reduced by roughly three to five percent, with positive float spacing tightened. The ACM body font, margins, and leading are unchanged. Repeated protocol prose is consolidated with its steps retained; the seven equation bodies remain unchanged. The final main body ends on page 18 and availability/references occupy page 19. Every final PDF page is visually reviewed. Exact manuscript changes and preservation checks are recorded in the paper's `qa/` directory.

## Reproduce the correction checks

Use a fresh output directory from the project root:

```bash
./GridWeave/.venv/bin/python research/GridWeave_Paper1/scripts/verify_contract_corrections.py \
  --output /tmp/gridweave-contract-verification
./research/GridWeave_Paper1/run-study test
```

The new script reads frozen public inputs, saves new predictions and comparison records, and never overwrites the historical study. Its output manifest pins the supplementary records. `preservation.json` verifies the protected historical file inventory. `before/manuscript/` retains the incoming editable paper and PDF; the final paper artifacts are independently identified by the paper's `qa/verification.json` and `contract_correction_manifest.json`.
