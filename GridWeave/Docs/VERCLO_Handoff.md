# GridWeave Dataset Handoff to VERCLO

Generate once, save the dataset and reuse it for later VERCLO runs. No verifier service or VERCLO execution is required to generate or validate data.

```bash
./gridweave generate --output datasets/my-data --seed my-study-seed --scales 1 2 4 --strategy all
./gridweave validate datasets/my-data
```

Alternatively, use the supplied datasets/reference pool. Copy a dataset as a complete directory and validate the copy against the recorded manifest digest. Each public index entry identifies the three native input files plus its policy and public verification context. Keep these bindings together.

The public subtree is sufficient for a compatible native consumer. Signed E2 inputs require their explicit public verification context; do not replace it with an unrelated key registry. The sealed subtree holds the generator's expected labels and reproduction material and belongs to the later evaluator, not the verifier input channel.

A consumer should read the existing public/index.json and associated per-unit files. It should not invoke GridWeave or import its oracle. Reusing the same immutable dataset permits repeated VERCLO runs without regenerating inputs. The parent research checkout's normal PaEForge run command accepts an existing dataset and dispatches the consumer only. That consumer is separate from this generator folder.

Dataset readiness establishes the declared interface, synthetic cryptographic fixture, expected-label and integrity checks. It does not claim completed downstream evaluation, physical erasure or electrical-grid simulation validity.
