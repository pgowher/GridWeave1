# Anonymization record

This is the reviewer copy of the GridWeave Paper 1 artifact. The original research archive remains intact. The [change inventory](anonymization-manifest.json) lists the files modified for this copy.

## Path redactions

Identifying directory prefixes in text and structured metadata were replaced with neutral placeholders. The remaining relative suffixes locate the corresponding evidence.

| Placeholder | Meaning |
| --- | --- |
| `${ARTIFACT_ROOT}` | Root of the recorded research workspace, with relevant paths preserved in the bundle |
| `${MANUSCRIPT_ROOT}` | Directory containing the manuscript workspace |
| `${ARCHIVE_ROOT}` | Historical external archive location |
| `${RECORDED_HOME}` | Recorded home directory |

These are display placeholders in the archived records. The executable entry points resolve their inputs within the downloaded bundle. All dataset files, public signatures, sealed labels, saved generation sources, predictions, raw utility observations and historical timing and memory measurements were preserved byte for byte.

## Integrity and execution

`SHA256SUMS` covers the reviewer copy. The two affected output manifests, the correction archive's source manifest and dependent provenance hashes were refreshed for the files they reference. Historical source freezes and the original preservation audit retain the identities they recorded at execution. Some historical indexes refer to original code versions or manuscript files outside this bundle. The three study corpus manifests retain their original hashes.

The bundle-specific runner updates let the structural census and single-extension replay use the saved generation sources. VERCLO’s structure check and integration tests use the shared reference corpus in the sibling project. The final reviewer copy omits duplicate corpora, superseded pilot outputs, and duplicate generated-corpus development comparisons. The main study runner, generator, assessors and evaluator labels are unchanged. The contract checker continues to resolve frozen dataset identities to the local copies.

The [verification record](submission-verification.json) reports the checks run on relocated copies. Measurements from these verification runs are separate from the historical measurements reported in the paper.

A full rerun rebuilds the separate fixtures with the active wire implementation. Its source hash is embedded in fixture provenance and receipt references, so the regenerated fixture manifest has a different hash. The bundled 98-fixture resource retains its original manifest. The paper’s byte-reproduction measurements concern the reference and structural-extension corpora.
