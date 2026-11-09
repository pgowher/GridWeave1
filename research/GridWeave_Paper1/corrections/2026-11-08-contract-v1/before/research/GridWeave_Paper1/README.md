# GridWeave paper research prototype

**Paper:** GridWeave Reproducible Authenticated Workloads for Evaluating Smart Grid Data Governance Evidence.

This workspace contains the executable research prototype, two independent semantic-checking implementations, a separately constructed fixture set, compatible VERCLO execution, matched-budget testing experiments and the manuscript. It uses the prepared local research environment. Licensing, clean installations and public release are not completion requirements for this task.

Run the paper studies from the project root:

```bash
./research/GridWeave_Paper1/run-study run
```

A completed run writes a fresh directory under `runs/`, with `REPORT.md`, `study_summary.json`, frozen predictions, populated semantic comparisons, raw utility observations and generation-cost measurements. The final recorded study is `runs/paper1-study-v1`. [RUNNING_THE_STUDY.md](RUNNING_THE_STUDY.md) documents the commands for fixtures, individual assessors, adjudication and tests.

## Implemented resource and studies

- The immutable reference corpus contains 420 units in 210 pairs from seven source families.
- The versioned structural extension adds 120 units in 60 pairs from six authored profiles, including joins, deeper lineage and cross-custodian replicas.
- The independent fixture builder creates 60 ordinary positive cases and 38 explicit semantic boundary cases without importing GridWeave, PaEForge or an assessor.
- GraphSpec uses graph traversal and explicit evidence rules. RelationalSpec uses recursive SQLite queries and relational aggregation. They share only wire-format utilities.
- The existing VERCLO consumer supplies a third implementation. Its invalid-exception handling and case-resource reporting were corrected using the new fixtures.
- Automated adjudication compares classes, baseline status, obligation categories and receipt diagnoses. Predictions are frozen before expected labels are joined.
- The utility study applies eight fault families to both new implementations, with three fixture conditions and five matched-budget subset repetitions.
- Repeated generation measurements record time, peak child resident memory and exact corpus reproduction.

The supported task is the declared default signed E2 profile. Algorithm and data-access independence do not imply blind authorship, human review or external institutional adoption. The same task authored the new software and fixtures. These limits are documented in the paper and semantic specification; they are not represented as completed human adjudication.

## Main files

- `GridWeave_Paper1_Working_Draft.docx` and `manuscript.md` contain the paper.
- `SEMANTIC_SPECIFICATION.md` defines the assessment rules and automated adjudication.
- `config/study_v1.json` records the executable study configuration.
- `paper1/` contains the active implementation and `tests/` its semantic and regression checks.
- `improvement_status.md` records completion within the requested research scope.
- `validation_protocol.md` describes the implemented study and evidence records.
- `LATEST_STUDY.json` identifies the latest completed run.
- `evidence/development_findings/` and `runs/development-study-1/` preserve failures and resolutions.
- `archive/v0_2/` retains earlier draft text, the toy fault pilot and blank human-review templates. These are historical artifacts, not active scaffolds.

The original GridWeave generation sources, saved labels and both pre-existing corpora remain unchanged. The paper prototype adds validation and experiment code outside that frozen baseline. The scope does not include physical erasure verification, discovery of undisclosed copies, higher evidence grades, field realism or a proof of general correctness.
