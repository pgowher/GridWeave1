# GridWeave paper research prototype

**Paper:** GridWeave Reproducible Authenticated Workloads for Evaluating Smart Grid Data Governance Evidence.

This study directory contains the executable experiments, two separate semantic-checking implementations, a separately constructed fixture set, and VERCLO consumer execution. The [artifact README](../../README.md) gives setup instructions and identifies the records supporting the paper.

Run the paper studies from the project root:

```bash
./research/GridWeave_Paper1/run-study run
```

A completed run writes a fresh directory under `runs/`, with `REPORT.md`, `study_summary.json`, frozen predictions, populated semantic comparisons, raw utility observations and generation-cost measurements. The final recorded study is `runs/paper1-study-v1`. [RUNNING_THE_STUDY.md](RUNNING_THE_STUDY.md) documents the commands for fixtures, individual assessors, adjudication and tests.

## Implemented resource and studies

- The immutable reference corpus contains 420 units in 210 pairs from seven source families.
- The versioned structural extension adds 120 units in 60 pairs from six authored profiles, including joins, deeper lineage and cross-custodian replicas.
- The independent fixture builder creates 60 ordinary positive cases and 38 explicit semantic boundary cases without importing GridWeave, PaEForge or an assessor.
- GraphSpec uses graph traversal and explicit evidence rules. RelationalSpec uses recursive SQLite queries and relational aggregation. They share wire utilities and envelope/profile validation, not assessment algorithms.
- The existing VERCLO consumer supplies a third implementation. Its invalid-exception handling and case-resource reporting were corrected using the new fixtures.
- Automated adjudication compares classes, baseline status, obligation categories and receipt diagnoses. Predictions are frozen before expected labels are joined.
- The utility study applies eight fault families to both new implementations, with three fixture conditions and five matched-budget subset repetitions.
- Repeated generation measurements record time, peak child resident memory and exact corpus reproduction.

The supported task is the declared default signed E2 profile. Algorithm and data-access independence do not imply blind authorship, human review or external institutional adoption. The same task authored the new software and fixtures. These limits are documented in the paper and semantic specification; they are not represented as completed human adjudication.

## Main files

- `SEMANTIC_SPECIFICATION.md` defines the assessment rules and automated adjudication.
- `config/study_v1.json` records the executable study configuration.
- `paper1/` contains the active implementation and `tests/` its semantic and regression checks.
- `validation_protocol.md` describes the implemented study and evidence records.
- `LATEST_STUDY.json` identifies the latest completed run.
- `evidence/development_findings/` and `runs/development-study-1/` preserve failures and resolutions.

The historical generation-source snapshots, saved labels and both pre-existing corpora remain unchanged. The active oracle and public loader have separately verified contract corrections; see `corrections/2026-11-08-contract-v1/verification/summary.json`. The historical 1,914-comparison study remains `runs/paper1-study-v1`; the correction verification is not pooled into that study. The scope does not include physical erasure verification, discovery of undisclosed copies, higher evidence grades, field realism or a proof of general correctness.

## Contract correction and historical reproduction

The active oracle enforces event <= submission <= evaluation and exactly one signature reference. Both new workers reject mismatched manifest/observer policy references (identifier, version or digest) and duplicate receipt IDs before assessment. The original 98-fixture catalogue is unchanged. Separate verification checks all four fields for the oracle on 638 saved units and both workers in 1,276 comparisons, three signature-cardinality probes, and 18 expected worker rejections across nine malformed variants. All 540 generated-unit labels are unchanged.

The corrected source and the historical generation snapshots have separate identities. Write new runs to fresh directories to preserve the saved measurements and labels.

Fresh full-study runs now replay the verified saved generation-source snapshots for historical corpus byte reproduction. Preparation is excluded from the timed child interval and the mode is recorded in `generation_sources.json`. Active corrected generation is still available through the normal GridWeave launcher and creates a new source identity. Future generation profiles record CPU, RAM, Python and dependency metadata in `host.json` before execution; this metadata is not evidence about the historical study host. The original timing medians remain historical observations.

Reproduce the separate contract verification into a fresh output directory:

```bash
./GridWeave/.venv/bin/python research/GridWeave_Paper1/scripts/verify_contract_corrections.py --output /tmp/gridweave-contract-verification
```
