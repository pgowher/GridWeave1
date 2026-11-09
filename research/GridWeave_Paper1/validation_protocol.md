# Executable validation protocol for the GridWeave paper

Version 1 dated 5 November 2026. This protocol is implemented by `paper1/study.py` and `config/study_v1.json`. It is a research-prototype experiment in the current workspace. Licensing, clean installations and public release are excluded from completion requirements.

## Questions and evidence

The study asks whether the saved labels agree with separately implemented semantics, whether compatible assessors can use the artifacts, and whether paired cases expose faults missed by ordinary positive fixtures. It also reports structural diversity, generation cost and exact reproduction. The results concern the declared signed E2 profile and synthetic cases, not operational erasure or a population of real defects.

## Corpus tracks

The first track is the preserved 420-unit, seven-family reference corpus. The second is the 120-unit structural extension with six authored native profiles. Both retain ten paired operations. Unit count, pair count, distinct input count and structural classes are reported separately using the existing census.

The third track contains 98 separately constructed native cases: 60 ordinary positive fixtures and 38 semantic boundary cases. The builder uses neither the generator nor an assessor. Expected final classes and category changes for boundary cases are literal declarations in `fixtures/semantic_cases_v1.json`; they are not outputs of the system being tested. Ordinary fixtures declare successful construction, including current exceptions, duplicate success statements and order changes. Shared wire-format primitives remain a common dependency and are disclosed.

## Implementations and independence

GraphSpec computes reachability through a queue, constructs per-replica obligations and applies explicit receipt, exception and class precedence. RelationalSpec reconstructs scope using recursive SQL and classifies obligations through database joins and aggregates. They import neither the original oracle nor each other’s assessment logic. VERCLO is a third related consumer with its own inference and evidence modules.

The two new implementations share serialization, hashing conventions and timestamp parsing. They were authored in this task after inspection of the existing profile, so the study claims implementation and data-access independence rather than independent human or blind authorship. No reviewer identity or judgment is fabricated.

## Prediction and label separation

The runner freezes implementation, fixture and configuration hashes, then copies only the public input tree to a temporary directory. Each assessor runs in a separate process. GraphSpec and RelationalSpec enforce and log their JSON input reads and reject generator or verifier imports. VERCLO records that no generator or oracle module was imported.

Complete per-case predictions and hashes are saved before the parent compares them with expected labels. The comparison verifies label inventory hashes and prediction hashes. It checks final class, baseline verifiability, the complete obligation-category map and matched receipt diagnoses. VERCLO abstains from intermediate reconstruction on unverifiable baselines; the report retains these unscored counts. The new checkers also compare the conditional reconstruction in those cases.

The runner stops before the utility experiment if any field disagreements remain. It never modifies a saved label to make a run pass. Development runs and resolutions remain available. The final run records the corrected implementation and fixture identities.

## Conformance and resolution records

The executable tests check all literal expectations with both new assessors, all seven final classes, all six obligation categories, cycle rejection, deterministic fixture reproduction and exact fault transformations. A native-consumer regression test verifies that unauthorized or temporally inadmissible exceptions are rejected without aborting a batch and that case-unit resources are evaluated with accurate family counts and label provenance.

The development study exposed an inadmissible-exception batch failure and ten field disagreements caused by inconsistent fixture event/submission times. The worker was corrected to record rejected assertions. Fixture version 1.1 corrects late-event submission timestamps and adds explicit malformed and future submission cases; both independent checkers enforce these conditions. Expected classes were not relabelled. `evidence/development_findings/resolutions.json` describes the decisions, and the original disagreement file is preserved under the development run.

## Testing utility

Eight deliberate fault families are applied once to each of the two new assessor implementations, yielding sixteen executable mutants. They bypass signatures, contradictions, declared scope, scope commitments, exception expiry or deadline precedence, or incorrectly reduce scope to roots or collapse replicas. The transforms operate on the independent implementations, not on the generator label oracle. Each transform must change exactly one declared semantic site, and its resulting code identity is frozen.

The three conditions are independently constructed ordinary positive fixtures, distinct GridWeave positive controls, and complete GridWeave control/challenge pairs. Each condition receives 40 case executions. The paired condition selects two pairs per operation. Five deterministic hash-based subsets are selected before predictions; these are repeated measurements, not independent populations. Source families, repeated controls and semantic input duplication remain explicit.

A mutant is detected when any of the four semantic output fields differs. The study saves per-case observations, per-mutant results, first detailed witnesses and detected-set differences. Surviving mutants remain in the denominator and are not called equivalent without evidence. Real consumer defects and deliberate mutants are reported separately. Ordinary positive fixtures can detect reconstruction faults; the study does not assume they are useless.

The experiment records assessment time and executed input bytes. Its principal comparison matches case-execution budgets. Timing excludes loading and is not used to claim a stable performance ranking or an independently repeated wall-time-budget experiment.

## Generation measurements

The runner regenerates both preserved corpora three times in separate child processes, sequentially after the assessor and utility stages. It records wall time including validation, peak resident memory for each child from wait4, output bytes and raw command logs. Memory is not presented as summed process-tree usage. Every regenerated manifest must match the preserved corpus digest; a difference fails the study.

All measurements use the existing local environment. No clean installation or public-release gate is imposed. These results establish the recorded execution profile, not cross-platform portability or a scaling law.

## Outputs and completion

A successful run produces nine dataset-by-assessor comparisons, raw disagreement records, 9,600 seeded-mutant case observations, generation records and an output hash manifest. `REPORT.md` and `study_summary.json` summarize the completed work. `LATEST_STUDY.json` is updated only after successful completion.

The prototype is ready for paper use when those checks complete without unresolved discrepancies, the existing consumer regressions pass and the paper claims match the resulting records. Human-independent adjudication, external adoption, arbitrary policy fragments, higher evidence grades and operational erasure remain outside the evidence claimed by this implementation.
