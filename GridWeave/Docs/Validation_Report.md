# GridWeave Standalone Validation Report

Checked on 25 October 2026 using the clean independent folder and its own Python environment. The frozen generation source identity remains 17512fe51989b0a9928ca6dbcacb0f8cb4a506d806e66038872851eb9724e98b.

| Check | Result |
|---|---|
| Frozen generation source identity | Unchanged |
| Generator construction and coverage property tests | 11 passed |
| Full standard reference dataset | 420 cases and 210 pairs validated |
| Supported oracle outcomes | All seven classes present |
| Family overlap between splits | None |
| Complete control/challenge pairs | Preserved |
| Native VERCLO case evaluations | 0 |
| Relocated runtime and local environment | Reproduced the 20-case reference byte for byte |
| Wrong trusted manifest digest | Rejected |
| Changed receipt file | Rejected |

The ready-to-use dataset is datasets/reference relative to GridWeave. Its manifest SHA-256 is:

```text
35778ae20cf2cda8a2c719b0713ee9c3fc2158eac75fb46679f35cae44db9b9f
```

Its manifest retains q_status=NOT_EXECUTED and a null downstream case-evaluation count. Modules and external Python packages were checked to load from inside the GridWeave folder. A runtime guard rejected any attempt to enter downstream evaluation functions; none were called.

The machine-readable record is [standalone-check.json](../validation/standalone-check.json). Recorded module paths for the relocated check identify its temporary test location; that temporary copy is removed after the check. These results establish the tested signed-E2 generator profile, saved input/label consistency and independent execution. They do not evaluate the VERCLO consumer or claim universal correctness outside the declared profile.
