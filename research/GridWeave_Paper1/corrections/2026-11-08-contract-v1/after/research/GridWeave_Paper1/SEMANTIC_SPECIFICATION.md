# Signed E2 assessment specification for the paper prototype

This specification defines the executable research task. GraphSpec and RelationalSpec implement it without importing the existing GridWeave oracle, generator or VERCLO assessment logic. They share serialization, hashing, timestamp parsing, public-input loading, and envelope/profile admission checks; those checks are a shared validation dependency. Their authoring occurred in this task after inspection of the existing profile. Independence therefore concerns code paths, algorithms and predictor access to labels; it is not blind or independent human authorship.

## Inputs and supported profile

The input consists of the five native public files for a unit: case manifest, observer projection, receipt stream, policy and verification context. Public file hashes, exchange commitments, case identifiers and the policy binding must agree. Both manifest and observer policy references must match the loaded policy's profile identifier, version and domain-separated digest. Receipt identifiers must be unique within a stream; duplicate identifiers and policy-reference mismatches are rejected before either new assessor executes. The profile supports a single default E2 rule, no overrides and no early closure. Evidence authenticates synthetic assertions against configured keys; it does not establish physical destruction or trustworthy real execution time.

Exchange commitments include the canonical JSON trailing newline. VERCLO scope, policy and obligation domain commitments exclude that trailing newline. Receipts and exception signatures sign the canonical JSON including the newline. These are wire-format conventions rather than scientific contributions.

## Obligations and baseline

Compute the assets reachable from all declared roots through directed lineage, including roots themselves. Every reachable replica whose asset kind and replica class match the policy creates a separate obligation. Its identity binds case, dataset, correlation, asset, replica, repository, custodian and policy identity/version. Several replicas of one asset therefore create several obligations.

A verifiable baseline requires an available graph, a complete declared scope, no unresolved references, known roots, a matching scope commitment and at least one applicable obligation. The graph must have unique identifiers, valid references and acyclic lineage. Unsupported or structurally malformed input is rejected explicitly rather than silently classified as a valid case.

## Receipt assessment

A matching receipt names the reconstructed obligation. Its case, asset, replica and repository must match, and its issuer must be the repository custodian. It must carry provenance, the supported E2 proof format, exactly one signature reference, a credential matching the externally configured issuer key, a matching claim digest and a valid Ed25519 signature. A receipt is currently usable only if its asserted event time is no later than its submission time, its not-before and submission times are no later than evaluation, and its optional expiry is strictly later than evaluation.

Authentication diagnosis is AUTHENTICATED_E2 or REJECTED for matched receipts. Evidence types signature, deletion_acknowledgement, replica_attestation and audit_finding can support this profile's terminal disposition. Other evidence types may be authentic but do not satisfy the terminal-evidence condition. Timeliness is event time at or before the default deadline. Authenticity and final obligation sufficiency are distinct.

## Exceptions and obligation precedence

A supported exception must have an admitted authority, a valid signature under configured authority keys, an effective time no later than the obligation deadline, and effective time at or before evaluation strictly before expiry. Invalid exceptions remain recorded as rejected assertions and do not abort other obligations. The current profile uses at most one exception assertion per obligation; ambiguous duplicate assertions are outside this fragment.

For each obligation apply these rules in order:

1. More than one distinct authenticated terminal disposition yields CONTRADICTORY.
2. Otherwise a current valid exception yields EXCEPTED.
3. Otherwise a timely authenticated permitted disposition yields COVERED.
4. Otherwise any authenticated late terminal statement yields LATE.
5. Otherwise no matching receipt yields MISSING.
6. Otherwise the obligation is INVALID.

## Case precedence

Before the default deadline the class is IN_PROGRESS. At or after the deadline, an unverifiable baseline yields UNVERIFIABLE. Otherwise any contradictory obligation or open declared challenge yields DISPUTED. All COVERED obligations yield CLOSED. All obligations COVERED or EXCEPTED yield CLOSED_WITH_EXCEPTIONS. A mixture containing at least one COVERED or EXCEPTED obligation yields PARTIALLY_CLOSED. Remaining cases yield OPEN.

Equal substantive inputs must have equal assessments; opaque transport IDs are not assessment features. Neither this invariance nor a positive class establishes absence of undeclared copies.

## Automated adjudication procedure

Freeze the implementations, fixture catalogue and study configuration. Run each assessor on a public-only copy, save complete predictions and their hashes, then compare with saved labels. Compare final class, baseline verifiability, complete obligation-category maps and matched receipt diagnoses. GraphSpec and RelationalSpec also cross-check conditional reconstructions under unverifiable baselines. VERCLO abstains from those intermediate claims when its baseline is invalid, so the report records that scoring coverage separately.

A disagreement stops the study before the utility experiment. Preserve the original prediction, label, source hashes and condition. Resolve a defect against this specification and the explicit boundary fixture, then rerun in a new output directory. Never edit a label merely to match an implementation. Human review can add evidence later, but is not fabricated or presented as completed here.

## Separately recorded contract correction (8 November 2026)

The active generator oracle now enforces event <= submission <= evaluation and exactly one Ed25519 signature reference. The common public loader now checks policy-reference identity/version/digest and receipt identity uniqueness. The historical `runs/paper1-study-v1` and its 98-fixture catalogue are unchanged. Supplementary verification is recorded under `corrections/2026-11-08-contract-v1/`: the corrected oracle matches all four fields over the 638 saved units, both corrected checker execution paths match all four fields in 1,276 comparisons, three signature-cardinality probes agree across the oracle and both checkers, and nine malformed-envelope variants are rejected by each new worker. None of the 540 generated-unit labels changes. These additional checks are not pooled into the historical study totals.
