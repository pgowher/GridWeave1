# GridWeave

GridWeave 0.2.1 is an independent synthetic smart-grid dataset generator for VERCLO research. It constructs and validates native signed-E2 inputs and their separate expected labels. Generation does not execute VERCLO.

## Run

The supplied local environment is ready on the recorded host. No parent project activation is required.

```bash
./gridweave --version
./gridweave generate --output datasets/my-data --seed my-study-seed --scales 1 2 4 --strategy all
./gridweave validate datasets/my-data
```

Invoke the launcher by its path from any working directory. Relative dataset paths resolve inside GridWeave. Starting it without arguments shows help; it never generates data implicitly. Its activities are generate and validate.

For a clean environment on another machine, install Python 3.11 or later and run `bash setup.sh` once. Setup creates `.venv` inside this folder and installs `requirements.txt`. The generator and both frozen support libraries are included locally.

## Ready-to-use reference dataset

`datasets/reference` is the full standard pool: 420 case units in 210 complete pairs, seven source families and seven closure classes. It is ready for later VERCLO input use after dataset validation:

```bash
./gridweave validate datasets/reference
```

VERCLO consumes these saved inputs separately; it does not regenerate them. The public tree contains inputs and policy/key configuration. The sealed tree contains evaluator-owned expected labels and reproduction material.

## Documentation

- [User Guide](Docs/User_Guide.md) and [Word edition](Docs/GridWeave_User_Guide.docx): setup, generation, settings and common problems.
- [Technical Guide](Docs/Technical_Guide.md) and [Word edition](Docs/GridWeave_Technical_Guide.docx): architecture, pair synthesis, oracle, coverage selection and validation.
- [Dataset Reference](Docs/Dataset_Reference.md): saved files and meanings.
- [VERCLO Handoff](Docs/VERCLO_Handoff.md): the saved-data boundary.
- [Reproducibility](Docs/Reproducibility.md) and [Validation Report](Docs/Validation_Report.md).

The original source snapshot and support libraries remain preserved in the reference corpus. `RESEARCH_FREEZE.json` and `SOURCE_MANIFEST.json` identify the historical pre-correction implementation, not the active corrected oracle. The 8 November 2026 correction adds submission-time and signature-cardinality admission checks; its source identities, regression tests and separate verification are recorded in `../research/GridWeave_Paper1/corrections/2026-11-08-contract-v1/`. No reference inputs or saved labels changed. New generation includes the corrected source identity; historical byte reproduction uses the recorded source snapshot. The source, support, schemas, configuration and required reference fixtures stay together. Old plans, reports, release packages and superseded documentation are excluded from this implementation folder.
