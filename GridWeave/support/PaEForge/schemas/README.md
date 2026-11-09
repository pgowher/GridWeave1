# Schema catalogue

All files use JSON Schema draft 2020-12 and are validated at package import. Their `$id` values are stable contract identifiers rather than network locations.

- `case-manifest-v1.schema.json`: safe case inventory and artifact bindings.
- `observer-projection-v1.schema.json`: the only case/topology projection admitted to VERCLO.
- `receipt-stream-v1.schema.json`: ordered receipt assertions and public proof references.
- `verclo-result-v1.schema.json`: frozen system-under-evaluation output.
- `evaluation-report-v1.schema.json`: evaluator-only post-run comparison.
- `run-manifest-v1.schema.json`: complete or failed vertical-run provenance and reproduction record.
- `middleware-envelope-v1.schema.json`: oracle-free distributed request wrapper around the unchanged verifier documents.
- `middleware-response-v1.schema.json`: frozen VERCLO result plus boundary timing observations.

The exchange schemas are deliberately closed. Extensions require a contract version change; producers must not add nullable or ignored truth fields. The two middleware schemas have an independent transport version and do not alter the frozen exchange bodies.
