# VERCLO research correctness and completion audit

Date: 26 October 2026. Implementation: VERCLO research 1.4.1.

The supplied signed-E2 study now completes and agrees with its saved reference labels. The audit also reproduced and corrected semantic errors that the standard dataset did not expose. This establishes a usable, checked research prototype for the declared study. It does not establish a general implementation-refinement theorem or a completed PhD contribution.

## Evidence and acceptance criteria

The complete existing GridWeave dataset was copied to `datasets/reference/`. All 2,843 files listed by its producer manifest match their recorded SHA-256 digests. No dataset was regenerated. Producer source snapshots remain inert dataset provenance; they are not on the verifier's import path.

Predictions were produced before evaluation. The verifier reads `public/`; a separate process first checks the frozen predictions, source identity, input commitments and diagnostics, then reads `sealed/` labels. Both consumer source trees and their schemas are included in the recorded run identity. Source identity is checked before and after prediction.

| Check | Observed result |
|---|---:|
| Saved closure labels matched | 420 / 420 |
| False positive closure decisions on this corpus | 0 |
| Missed positive closure decisions on this corpus | 0 |
| Scored obligation categories matched | 2,646 / 2,646 |
| Scored receipt-authentication decisions matched | 2,457 / 2,457 |
| Permutation and hidden-copy-twin pair checks | 42 / 42 |
| Manually specified model-to-code cases | 18 / 18 |
| Bounded abstract-model configurations checked | 8,087 |
| Research tests | 131 passed |
| Additional subtests | 384 passed |
| Generator/oracle modules loaded during prediction | None |

Obligation and authentication comparisons are scored where the saved baseline is verifiable. An unverifiable scope is judged by its closure outcome rather than treating unavailable obligation classifications as ordinary missing predictions. The output tables explicitly identify scored rows.

The materialized 420 units share seven synthetic source families and paired transformations. They are not 420 independently sampled real deployments. No independent-sample confidence interval or field-generalization claim is inferred. The reference oracle is separately implemented within this project, not independently authored validation.

## Demonstrated defects and corrections

Before correction, the standard corpus already yielded 420 matching closure labels. However, the separate 18-case check reproduced four model mismatches: an unexplained empty graph, a challenge before readiness, an invalid baseline before readiness and an exception exactly at expiry. Two produced unsafe positive closure relative to the stated abstract conditions. This is why execution success and standard-corpus agreement were insufficient.

| Finding | Correction and research significance |
|---|---|
| Unattested empty graphs could close | Empty scopes fail closed, even if a manually supplied graph marks itself verifiable. |
| Decision precedence differed from the model | Readiness precedes terminal baseline/dispute classification. Early decision requires terminal reports, including authenticated failure reports. |
| Exception expiry and effective time were incomplete | Validity uses `effective_at <= evaluation_time < expires_at`. |
| Future event/submission evidence could participate | Such evidence remains unavailable until its timestamps are reached; impossible event/submission ordering is rejected. |
| E5 corroboration counted dependent or repeated witnesses | Witness roles, unique principals, event binding and distinct trust/fault domains are checked. Conventional bipartite matching counts independent domains. |
| Unrelated ordering evidence could upgrade a primary assertion | Supporting anchors require explicit primary-receipt and claim-commitment references. The conformance input fixture supplies these links rather than assuming them. |
| A late higher-grade receipt could hide timely sufficient evidence | Primary selection prefers closure-admissible evidence before grade. |
| Conflicting duplicate receipt IDs depended on collection order | Conflicting content under one ID is rejected in either order. |
| Incremental reuse missed evidence-availability boundaries | Event and submission times are included in frontier invalidation. |
| A synthetic validation backend could be selected implicitly | Normal bundle evaluation requires a trust context; synthetic validation requires explicit test-only opt-in. |
| Run identity omitted part of the consumer | The identity covers both source trees, exchange schemas and package metadata. |
| Research outputs were incomplete | Detailed diagnostics and separate saved-label evaluation now accompany the frozen predictions. |

The corrections are checked by counterexample tests, existing protocol/evidence tests, differential incremental/full recomputation tests, the abstract-model cases and the fresh dataset execution. The test suite also exercises malformed input, input tampering, prediction tampering and portability without a GridWeave tree. Tests for signature, Merkle and PBFT backends use local loopback servers; they do not establish arbitrary-network performance or a universal Byzantine-safety proof.

The machine-readable findings and before/after evidence are in [the audit directory](results/audit-2026-10-26/). The original source hashes and the pre-correction mismatch report are retained as audit evidence; duplicate historical implementation trees were removed.

## Algorithm and component assessment

| Component | Inputs and result | Assessment |
|---|---|---|
| Obligation discovery | Declared roots, topology and policy to reachable assets and per-replica obligations | Canonical graph construction, cycle/reference checks, alternative traversal comparisons and corpus obligation IDs checked. Traversal is O(V+E), followed by canonical sorting and obligation construction. |
| Receipt verification and E0–E5 grading | Case-bound evidence plus configured backend facts to admissibility and capabilities | Signed-E2 dataset checks and targeted higher-grade conformance cases pass. Higher capabilities remain conditional on trustworthy backend facts and bindings. |
| Closure decision | Obligation classifications, exceptions, challenges and decision time to seven operational outcomes | The 18 manually specified cases now match the independent abstract relation. Finite correspondence is not an unbounded code-refinement proof. |
| Receipt indexing | Receipt collection to obligation partitions | Conventional O(R) grouping; full reports still visit the obligation set. |
| Temporal frontier | Immutable validation snapshots, epochs and time changes to reused/recomputed evidence bundles | Differential checks cover changes, expiry, availability boundaries, disputes and epoch replacement. Full-report materialization remains O(O); reuse relies on explicit revocation/epoch updates. |
| Corroboration independence | Admitted witness/domain bindings to a threshold decision | Conventional matching, with O(W*E) matching work for the witness-domain graph after construction; no novelty claim is made for matching or indexing. |
| C-PaE primitives | Messages, credentials, replay state and supplied transition facts to authenticated/guarded transitions | Conformance components are tested. This is not a complete proof that a distributed message history refines the abstract protocol. |
| Network trust anchors | Receipt/decision material to signed, Merkle or quorum-backed validation facts | Focused local fault/certificate checks pass. A certificate authenticates the supplied decision facts; it does not establish physical erasure. |

The audit inspected 36 core Python modules and 16 consumer/contract Python modules, together with their policies, schemas, tests and formal companions. It added focused correctness checks and research evaluation outputs rather than deployment or commercial-release infrastructure.

## Required outputs and current locations

[Current predictions](results/reference-final-2026-10-26/predictions/) contain:

- One schema-validated result per dataset unit, with closure, obligation classifications, reason codes, input commitments and provenance.
- Per-unit diagnostics containing the inferred obligation graph, receipt checks and evidence bundles.
- `source-identity.json` and a `COMPLETE` `results-manifest.json` binding the source, public index and output hashes.

[Current evaluation](results/reference-final-2026-10-26/evaluation/) contains:

- `evaluation.json`: acceptance results, mismatch registers, sampling units and claim limits.
- `cases.csv`, `obligations.csv` and `receipts.csv`: detailed observed/reference comparisons.
- `confusion_matrix.csv` and `condition_metrics.csv`: closure confusion and results by split, family, operation and scale.
- `metamorphic_pairs.csv`: the permutation and hidden-copy-twin checks.
- `output-manifest.json`: hashes of the evaluation artifacts.

These files provide the required results for the declared saved-data study. The `executed_operations_q` field in each prediction is a logical workload counter: two document adapters plus discovered obligations and input receipts. It is not a count of CPU instructions or cryptographic operations. Per-call duration measurements are descriptive and do not establish a scalability or speedup result.

## Remaining research limits

The native study trusts acquisition of the saved dataset, policies, scope and public-key configuration. Hash agreement establishes consistency with that acquisition; it does not independently authenticate every authorization, scope or timing assertion required by the broader formal model. Synthetic E2 signatures authenticate configured claims and cannot establish the real execution time of deletion or exclude backdating by a dishonest signer.

The provided corpus exercises signed E2. Higher grades have targeted conformance checks, but this corpus does not validate real mechanism attestations, arbitrary policy profiles or universal distributed executions. The native profile has no authenticated no-applicable-obligation certificate, so empty scopes are rejected. Incremental snapshots require a trusted supplier to communicate revocation and epoch changes.

The executable abstract model passed its tests and 8,087 bounded checks. Lean sources were retained, including the effective-time condition. Their current build was not executed locally because Lean/Lake is unavailable. Existing abstract safety theorems, even when compiled, do not by themselves prove that all implementation paths refine the model. Current finite checks, independent external evaluation and an unbounded implementation argument remain distinct evidence requirements.

No physical-deletion, hidden-copy-absence, automatic legal-compliance, global novelty or thesis-completion claim follows from this audit.

## Cleanup

The old documentation, publication/release trees, duplicate source snapshots, stale results and obsolete generator/deployment paths were removed from VERCLO. Executable formal models, current algorithms, consumed conformance data and the complete supplied dataset were retained. The new README and this audit replace the previous documentation. GridWeave was left unchanged. [cleanup.json](results/audit-2026-10-26/cleanup.json) records the removals.
