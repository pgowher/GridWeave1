# GridWeave paper 1 executable study results

Study GridWeave-Paper1-Study-1.0. Status COMPLETE. All counts describe the declared synthetic signed E2 profile.

## Semantic assessment and adjudication

| Dataset | Assessor | Cases | Class matches | Field disagreements |
| --- | --- | --- | --- | --- |
| reference | graph | 420 | 420 | 0 |
| reference | sql | 420 | 420 | 0 |
| reference | verclo | 420 | 420 | 0 |
| structural_extension | graph | 120 | 120 | 0 |
| structural_extension | sql | 120 | 120 | 0 |
| structural_extension | verclo | 120 | 120 | 0 |
| independent_fixtures | graph | 98 | 98 | 0 |
| independent_fixtures | sql | 98 | 98 | 0 |
| independent_fixtures | verclo | 98 | 98 | 0 |

The graph and SQLite checkers share wire serialization only, and import neither the generator nor VERCLO assessment code. VERCLO is a separate related consumer. All read public input copies only. These are independent implementations with same-task nonblind AI authorship, not human-independent judgments. The separate fixture catalogue supplies ordinary positive constructions and explicit semantic boundary expectations; counts and catalogue versions are recorded below.

## Matched-budget testing utility

| Repetition | Ordinary positive detected | GridWeave positive detected | GridWeave pairs detected | Pair-only beyond ordinary |
| --- | --- | --- | --- | --- |
| 0 | 4 | 4 | 16 | 12 |
| 1 | 4 | 4 | 16 | 12 |
| 2 | 4 | 4 | 14 | 12 |
| 3 | 4 | 4 | 16 | 12 |
| 4 | 4 | 4 | 14 | 12 |

The experiment uses 16 deliberate mutants from eight fault families across two assessor implementations, 40 executions per condition, and 5 deterministic subset repetitions. Detection includes incorrect obligation or receipt diagnoses as well as incorrect case classes. It does not estimate a population of real bugs.

## Generation cost and byte reproduction

| Corpus | Repetitions | Median seconds including validation | Median peak child MiB |
| --- | --- | --- | --- |
| reference | 3 | 125.20 | 72.11 |
| structural_extension | 3 | 30.39 | 66.14 |

All measured regenerations reproduced their recorded corpus manifests byte for byte in the existing research environment. Memory is the peak resident memory of each generator child process, not summed process-tree memory.

## Readiness and limits

The current-workspace prototype has a runnable study, frozen outputs, machine-readable disagreement records, conformance checks and raw utility observations. Licensing, clean dependency installations and public release are outside the requested completion scope. Higher evidence grades, physical deletion, undisclosed-copy detection, field realism and independent human adjudication are not claimed.

Run definitions, source identities, predictions, comparisons and fault observations are retained beside this report. A disagreement must be inspected; this runner never rewrites a saved label to force agreement.
