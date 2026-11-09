# VERCLO research implementation

VERCLO evaluates observer-relative erasure closure from an existing native dataset. This folder contains the implementation, executable formal models, and focused tests. It reads the shared GridWeave reference corpus from the sibling project folder. It runs without starting or importing GridWeave.

## Run and evaluate

After running the setup script, run these commands from this folder:

```bash
./verclo validate ../GridWeave/datasets/reference
./verclo run --dataset ../GridWeave/datasets/reference --output results/my-study/predictions
./verclo evaluate --dataset ../GridWeave/datasets/reference --run results/my-study/predictions --output results/my-study/evaluation
```

Use a fresh output directory for every execution and evaluation. Relative paths resolve inside this VERCLO folder; absolute paths are accepted. Another dataset must retain its native public index, case inputs, policies and public verification contexts. Evaluation additionally requires its saved sealed labels and producer manifest. Arbitrary CSV or Parquet files need conversion to the native contract.

Verification reads the public tree only. The separate evaluation process verifies the frozen prediction files before reading saved expected labels. A successful prediction run ends with a COMPLETE results-manifest.json. It produces per-case results, graph/receipt/evidence diagnostics and a consumer source identity. Evaluation produces evaluation.json, cases.csv, obligations.csv, receipts.csv, confusion_matrix.csv, condition_metrics.csv, metamorphic_pairs.csv and an output hash manifest.

See the [Paper 1 study](../research/GridWeave_Paper1/runs/paper1-study-v1/) for the consumer predictions and adjudication used in this paper. The [research audit](RESEARCH_AUDIT_2026-10-26.md) describes an earlier VERCLO study.

## Setup and focused checks

On another machine, use Python 3.11 or later and run bash setup.sh. For tests also install the small research dependency set with bash setup.sh --research. Recreate the virtual environment after relocating this folder. Fresh installation needs access to the declared Python packages.

```bash
./verclo check
./verclo tests
.venv/bin/python research/audit_model.py --output results/my-model-check.json
.venv/bin/python formal/check_safety.py
```

Tests for network trust anchors open local loopback servers. The explicit setup option --use-system-packages is available for a host that already has the dependencies. Optional Lean proof checking uses the toolchain pinned under formal/; it is separate from dataset verification.

## Current files

- HTGLThesis/src/: closure, policy, evidence grades, protocol and trust-backend algorithms.
- PaEForge/src/ and PaEForge/schemas/: native input contracts, execution, diagnostics and separate evaluation.
- formal/: retained executable abstract model and Lean source.
- research/: manually specified model-to-code boundary cases.
- ../GridWeave/datasets/reference/: the shared GridWeave reference corpus, including evaluator labels and producer provenance.
- results/: default location for newly generated predictions and evaluations.

The supplied dataset has seven synthetic source families and 420 paired case units. Its labels are independently implemented within the same project, rather than independently authored validation. Agreement on this corpus and passing finite checks do not prove general correctness. E2 signatures authenticate configured assertions; they do not establish real execution time, physical deletion, absence of undisclosed copies or legal compliance.
