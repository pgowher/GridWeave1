# GridWeave Reproducibility

The frozen generation source identity is:

```text
17512fe51989b0a9928ca6dbcacb0f8cb4a506d806e66038872851eb9724e98b
```

RESEARCH_FREEZE.json records the declared implementation profile. SOURCE_MANIFEST.json records the actual generation file hashes, with all source roots inside GridWeave. The wrapper and environment setup are separate from the frozen generation algorithms.

Keep source, support and required resources together. The launcher locates them relative to itself and uses .venv inside GridWeave. It does not activate the parent environment. Python is an operating-system prerequisite; setup.sh installs the pinned external requirements into the local environment. Rebuild the environment when moving between operating systems or Python ABIs.

For exact dataset reproduction, retain the same source bytes, support definitions, seed, selected source profiles, sorted scale factors, strategy, state cap and audit flag. These generation parameters are saved in sealed/reproduction.json. Generate into a fresh directory and compare the manifest SHA-256. Retain the trusted digest outside the dataset; a self-consistent manifest alone does not authenticate a publisher.

```bash
./gridweave validate datasets/reference --expected-sha256 YOUR_RECORDED_MANIFEST_SHA256
```

Replace the placeholder with the actual recorded 64-character digest. Never repair changed data by manually changing expected labels or recomputing its inventory. Regenerate from recorded inputs instead.

The current check copies the runtime and its own environment outside the combined repository and reproduces a fixed-seed 20-case dataset byte for byte. This demonstrates independence from sibling projects and the parent environment. Run the included generation-only check from GridWeave with `.venv/bin/python tools/check_standalone.py`; it never runs VERCLO. The current result is validation/standalone-check.json.
