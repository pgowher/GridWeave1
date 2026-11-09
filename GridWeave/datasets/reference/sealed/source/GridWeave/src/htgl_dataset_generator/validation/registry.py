"""Mandatory S13 check metadata and extension-safe registry construction."""

from __future__ import annotations

from typing import Iterable, Mapping

from htgl_dataset_generator.config import CORE_VALIDATION_CHECK_IDS

from .models import RegisteredValidationCheck, ValidationCheckSpec


VALIDATOR_VERSION = "S13.joint-validator.v1"


_CORE_METADATA: Mapping[str, tuple[str, str, str]] = {
    "SCHEMA-001": ("schema", "fatal", "all implemented authoritative rows satisfy the locked Arrow schema"),
    "IDENTITY-001": ("artifact", "fatal", "all declared primary keys are unique in their table scope"),
    "FK-001": ("artifact", "fatal", "all declared cross-table references resolve"),
    "TEMPORAL-001": ("temporal", "fatal", "all lifecycle intervals and event order constraints are valid"),
    "PHYSICAL-001": ("physical", "error", "physical units, continuity, bounds, balance and convergence checks pass"),
    "TEMPORAL-ARRIVAL-001": ("temporal", "error", "the configured arrival model passes its statistical diagnostics"),
    "WORKFLOW-001": ("workflow", "fatal", "non-anomalous workflow transitions, roots, counts and deadlines conform"),
    "DAG-001": ("topology", "fatal", "the normalized required-edge graph is acyclic and closure/depth truth recomputes"),
    "POLICY-001": ("policy", "fatal", "policy decisions and golden cases independently recompute with provenance"),
    "ANOMALY-001": ("anomaly", "fatal", "accepted anomalies violate only the target under the declared bounded grammar"),
    "EVIDENCE-001": ("evidence", "fatal", "obligations, receipts, verification and sufficiency truth independently recompute"),
    "OBSERVER-001": ("observer", "fatal", "projection, omission, release-view and task-sufficiency checks pass"),
    "SAMPLING-001": ("sampling", "fatal", "probabilities, weights, closure provenance and estimator gates pass"),
    "N-N-Q-001": ("sampling", "fatal", "represented N, materialized n and executed q remain distinct and reconciled"),
    "PRIVACY-001": ("privacy", "fatal", "released observer records contain no sealed labels or protected identifiers"),
    "PRIVACY-SOURCE-001": ("privacy", "warning", "source-membership privacy evaluation executes or has an explicit non-applicability justification"),
    "RECONCILIATION-001": ("topology", "error", "cohort, arrival, workflow, represented-root and metric counts reconcile"),
    "REPLICATE-001": ("artifact", "fatal", "every declared scenario/replicate retains seed evidence and per-replicate metrics"),
    "MANIFEST-001": ("artifact", "fatal", "every final stored payload occurs once with correct bytes, rows, schema and SHA-256"),
    "REPRODUCIBILITY-001": ("artifact", "fatal", "a clean rerun reproduces every canonical authoritative table digest"),
    "PERFORMANCE-001": ("performance", "error", "measured performance satisfies the pinned threshold profile"),
}


def core_check_specs() -> tuple[ValidationCheckSpec, ...]:
    """Return stable metadata for every non-removable core check."""

    if set(_CORE_METADATA) != set(CORE_VALIDATION_CHECK_IDS):
        missing = sorted(set(CORE_VALIDATION_CHECK_IDS) - set(_CORE_METADATA))
        extra = sorted(set(_CORE_METADATA) - set(CORE_VALIDATION_CHECK_IDS))
        raise RuntimeError(f"core validation metadata mismatch missing={missing} extra={extra}")
    return tuple(
        ValidationCheckSpec(check_id, domain, severity, condition, VALIDATOR_VERSION)
        for check_id, (domain, severity, condition) in sorted(_CORE_METADATA.items())
    )


def build_check_registry(
    core_runners: Mapping[str, object],
    *,
    required_check_ids: Iterable[str],
    extensions: Iterable[RegisteredValidationCheck] = (),
) -> tuple[Mapping[str, ValidationCheckSpec], Mapping[str, object]]:
    """Build a complete profile without allowing extensions to replace core checks."""

    specs = {item.check_id: item for item in core_check_specs()}
    runners = dict(core_runners)
    if set(runners) != set(CORE_VALIDATION_CHECK_IDS):
        missing = sorted(set(CORE_VALIDATION_CHECK_IDS) - set(runners))
        extra = sorted(set(runners) - set(CORE_VALIDATION_CHECK_IDS))
        raise RuntimeError(f"core validation runner mismatch missing={missing} extra={extra}")
    for extension in extensions:
        check_id = extension.spec.check_id
        if check_id in CORE_VALIDATION_CHECK_IDS:
            raise ValueError(f"extension cannot replace mandatory core check {check_id}")
        if check_id in specs:
            raise ValueError(f"duplicate extension check {check_id}")
        specs[check_id] = extension.spec
        runners[check_id] = extension.runner
    for check_id in required_check_ids:
        if check_id not in specs:
            specs[check_id] = ValidationCheckSpec(
                check_id=check_id,
                domain="artifact",
                severity="fatal",
                expected_condition="a versioned validator implementation is registered",
                validator_version=VALIDATOR_VERSION,
            )
    return dict(sorted(specs.items())), dict(sorted(runners.items()))

