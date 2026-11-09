# Running the GridWeave paper prototype

The prototype uses the prepared GridWeave environment in this workspace. It provides a complete executable experiment for the paper’s declared signed E2 profile. Licensing, clean installations and public distribution are outside this research task’s completion scope.

## Run all paper studies

From the project root:

```bash
./research/GridWeave_Paper1/run-study run
```

This creates a fresh timestamped directory under `research/GridWeave_Paper1/runs`. To choose the location:

```bash
./research/GridWeave_Paper1/run-study run --output /tmp/gridweave-paper1-study
```

Use a new output directory for every run. The command performs semantic conformance and consumer regression tests, constructs the independent fixture set, runs GraphSpec, RelationalSpec and VERCLO on public-only copies, freezes predictions, compares labels and intermediate semantics, runs the utility experiment and measures repeated generation cost and byte reproduction. It stops and preserves records if a semantic disagreement occurs. A completed run produces `REPORT.md`, `study_summary.json`, raw CSV observations, prediction manifests, an output manifest and a `LATEST_STUDY.json` pointer in the paper workspace.

The final recorded execution is in `runs/paper1-study-v1`. New runs retain the original reference corpus and the versioned structural extension unchanged.

## Use the components separately

Run the conformance and consumer regression checks:

```bash
./research/GridWeave_Paper1/run-study test
```

Construct the independent fixtures:

```bash
./research/GridWeave_Paper1/run-study fixtures --output /tmp/paper1-fixtures
```

Run an independent assessor using the fixture’s public inputs:

```bash
./research/GridWeave_Paper1/run-study assess \
  --dataset /tmp/paper1-fixtures --assessor sql --output /tmp/paper1-sql-predictions
```

Choose `graph` for GraphSpec or `sql` for RelationalSpec. Compare the frozen predictions with the separately saved expectations:

```bash
./research/GridWeave_Paper1/run-study adjudicate \
  --dataset /tmp/paper1-fixtures --predictions /tmp/paper1-sql-predictions \
  --assessor sql --output /tmp/paper1-sql-adjudication
```

The existing VERCLO consumer is a third compatible assessor:

```bash
./VERCLO/verclo run --dataset /tmp/paper1-fixtures --output /tmp/paper1-verclo-predictions
./research/GridWeave_Paper1/run-study adjudicate \
  --dataset /tmp/paper1-fixtures --predictions /tmp/paper1-verclo-predictions \
  --assessor verclo --output /tmp/paper1-verclo-adjudication
```

Rebuild a completed result report without repeating the experiment:

```bash
./research/GridWeave_Paper1/run-study report \
  --run research/GridWeave_Paper1/runs/paper1-study-v1
```

## Study components

- `paper1/graph_assessor.py` reconstructs obligations through graph traversal and applies explicit per-obligation rules.
- `paper1/sql_assessor.py` uses recursive SQLite queries and relational aggregation.
- `paper1/fixture_builder.py` constructs native inputs from separate ordinary structures and explicit boundary expectations. It does not import GridWeave, PaEForge or an assessor.
- `paper1/assessor_worker.py` reads a public-only input root and freezes predictions. Its JSON read guard and module record make label access inspectable.
- `paper1/adjudication.py` compares classes, baseline status, complete obligation categories and receipt diagnoses, with scoring coverage reported explicitly.
- `paper1/utility.py` executes eight deliberate fault families in both independent implementations over three fixture conditions and five matched-budget subset repetitions.
- `paper1/profiling.py` records three generation repetitions for each saved corpus, child peak resident memory, byte reproduction and raw logs.
- `config/study_v1.json` records the experiment configuration and research scope.
- `SEMANTIC_SPECIFICATION.md` defines supported meanings and precedence.

GraphSpec and RelationalSpec share serialization and time parsing, not assessment algorithms. Their independence is computational and methodological: they do not import the generator or its oracle and run without label access. They were authored in this task with knowledge of the existing profile. They are not independent human judgments or evidence of external institutional adoption.

## Reading the evidence

Each dataset/assessor comparison records `summary.json`, `cases.csv` and `disagreements.json`. The two new checkers compare conditional obligation reconstruction even when the declared baseline is unverifiable. VERCLO abstains from those intermediate claims, and its unscored coverage is recorded. A final class match alone is not treated as complete semantic agreement.

The utility experiment counts a mutant as detected when a case class, baseline judgment, obligation map or matched receipt diagnosis differs. It retains survivors and detailed witnesses. The sixteen mutants represent eight fault families across two implementations; they are not sixteen independently observed operational bugs. Positive fixtures can expose structural reconstruction faults, while paired cases additionally exercise evidence defects.

The development record preserves a rejected-exception batch failure and a fixture timestamp construction error. Corrections were made to the relevant code and inputs, without changing expected labels to force agreement. Earlier draft scripts, blank human-review templates and pilot outputs are historical material, not unfinished requirements of the active workflow.
