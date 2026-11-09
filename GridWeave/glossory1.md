# GridWeave Paper 1 — Quick notation and variable legend

The following symbols are proposed for the manuscript and correspond to the implemented default signed E2 profile.

| Symbol | Meaning |
|---|---|
| \(u_i\) | One evaluation unit: a saved case with its public inputs and evaluator-owned labels. |
| \(G_i=(A_i,L_i)\) | Declared asset-lineage graph, with assets \(A_i\) and directed derivation edges \(L_i\). |
| \(C_i,S_i,R_i\) | Sets of custodians, repositories and replicas represented in the case. |
| \(A_i^0\) | Declared root assets for the lifecycle request. |
| \(A_i^\star\) | Assets reachable from the roots, including the roots themselves. |
| \(P_i,K_i\) | Applicable policy and verification context, including configured public keys. |
| \(\mathcal O_i\) | Reconstructed obligations: one for each reachable replica matching policy applicability. |
| \(E_i,X_i\) | Submitted receipts and declared exception assertions, respectively. |
| \(t_i^0,t_i,d_i\) | Case acceptance time, evaluation time and obligation deadline. |
| \(b_i\) | Boolean baseline-verifiability judgment under the supported profile. |
| \(\gamma_i(o)\) | Assessment category assigned to obligation \(o\). |
| \(\alpha_i(e)\) | Authentication diagnosis assigned to a matched receipt \(e\). |
| \(y_i,\widehat y_i^{(a)}\) | Expected case class and case class predicted by assessor \(a\). |
| \((u_j^{c},u_j^{h})\) | Control and challenge members of pair \(j\). |
| \(w_i\) | Evaluator-owned latent annotation, such as undeclared-copy presence. |
| \(H,\sigma,pk\) | SHA-256 hash function, Ed25519 signature and configured verification public key. |

The supported deadline rule is

\[
d_i=t_i^0+\Delta(P_i),
\]

where \(\Delta(P_i)\) is the policy’s default deadline offset. Receipt timeliness requires `event_time` \(\le d_i\); separate admissibility checks govern submission, validity and evaluation times.

## Assessment values

| Variable | Supported values |
|---|---|
| \(\gamma_i(o)\) | COVERED, EXCEPTED, MISSING, INVALID, LATE, CONTRADICTORY |
| \(\alpha_i(e)\) | AUTHENTICATED_E2, REJECTED |
| \(y_i,\widehat y_i^{(a)}\) | CLOSED, CLOSED_WITH_EXCEPTIONS, PARTIALLY_CLOSED, OPEN, DISPUTED, UNVERIFIABLE, IN_PROGRESS |

## System and experiment variables

| Variable or field | Meaning and current use |
|---|---|
| \(N_f\): `N_synthetic_source_families` | Family groups within a resource. The preserved reference has seven source families; structural profiles and fixture structures should be reported separately. |
| \(n\): `n_materialized_cases` | Saved evaluation units: 420 reference, 120 extension and 98 separate fixtures; 638 overall. |
| \(p\): `materialized_pairs` | Complete control/challenge pairs: 210 reference and 60 extension. The separate fixtures are unpaired. |
| \(q\) | Executed assessor–case evaluations for a specified experiment: 1,914 semantic comparisons or 9,600 mutation-study observations. |
| `q_status` | Generation manifests retain `NOT_EXECUTED`; separate study records document subsequent assessor execution. |
| \(M\) | Sixteen deliberate mutants representing eight fault families across two implementations. |
| \(B\): `utility_case_budget` | Forty case executions per utility condition and subset. |
| \(R\): `utility_repetitions` | Five deterministic subset repetitions. |
| `generation_repetitions` | Three measured regenerations per corpus. |
| `proof_profile` | Synthetic signed E2 evidence under configured keys. |
| `source_snapshot_sha256` | Identity of the recorded generation-source snapshot. |

Case counts, pair counts, distinct structures and execution counts describe different quantities. Authenticated evidence supports assessment within declared observable scope; it does not establish physical deletion or absence of hidden copies.
