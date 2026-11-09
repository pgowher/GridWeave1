# Saved VERCLO inputs

The reviewer repository stores the complete reference corpus under [GridWeave datasets](../../GridWeave/datasets/reference/), including the public inputs, sealed expected labels, and producer provenance. You can also place additional native datasets in this directory.

```text
datasets/my-data/
  public/
    index.json
    cases/UNIT/
      case-manifest.json
      observer-projection.json
      receipt-stream.json
    configuration/UNIT/
      policies/policy.json
      verification-context.json
  dataset-manifest.json       # required for label-based evaluation
  sealed/cases/UNIT.json      # required for label-based evaluation
  sealed/pairs.json           # required for label-based evaluation
```

The public index format is `GridWeave-0.2.0`. Each entry names a unique lowercase 32-character hexadecimal unit ID and SHA-256 bindings for exactly the five public files above. The native export includes explicit synthetic Ed25519 public-key configuration. Signatures authenticate configured assertions; they do not establish ordering, trustworthy real execution time or physical erasure.

```bash
./verclo validate datasets/my-data
./verclo run --dataset datasets/my-data --output results/my-data/predictions
./verclo evaluate --dataset datasets/my-data --run results/my-data/predictions --output results/my-data/evaluation
```

Prediction reads only the public index, bound public documents and configuration. It does not load sealed labels or execute saved generator snapshots. The separate evaluator verifies frozen predictions before reading saved labels. A public-only dataset can be used for prediction; this evaluator additionally needs the complete saved label structure and producer manifest.

Choose fresh output directories outside datasets and source folders. Input binding failures stop normal processing. Trust in the index, policy, scope and key configuration comes from dataset acquisition, not merely hash consistency. See the [VERCLO instructions](../README.md) for execution and evaluation.
