"""Frozen publication profiles and their permitted scientific claims."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping


PROCEDURAL_CONTROLLED_SYNTHETIC_V1 = "procedural-controlled-synthetic-v1"


class ReleaseProfileError(ValueError):
    """Raised when a resolved run exceeds its selected publication profile."""


@dataclass(frozen=True)
class ReleaseProfile:
    profile_id: str
    profile_version: str
    physical_backend: str
    physical_backend_version: str
    analytic_state_backend: str
    required_source_label: str
    permitted_claims: tuple[str, ...]
    prohibited_claims: tuple[str, ...]
    physical_validity_scope: str
    profile_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_PROFILE_CORE: Mapping[str, Any] = {
    "profile_id": PROCEDURAL_CONTROLLED_SYNTHETIC_V1,
    "profile_version": "1.0.0",
    "physical_backend": "procedural",
    "physical_backend_version": "procedural.v1",
    "analytic_state_backend": "procedural_analytic:v1",
    "required_source_label": "controlled_synthetic",
    "permitted_claims": (
        "deterministic generation under the resolved configuration and named seed streams",
        "schema, workflow, causal-DAG, policy-oracle, evidence-fixture, observer, sampling, manifest, and reproducibility results that passed their declared checks",
        "controlled procedural-model physical constraint validity within the configured units and bounds",
        "design-based estimates only for estimator-eligible samples with valid inclusion probabilities",
        "represented population N, materialized rows n, and externally replayed operations q only as separate quantities",
    ),
    "prohibited_claims": (
        "external physical-backend integration or conformance",
        "calibrated fidelity to an observed population",
        "external power-flow solver convergence",
        "legal compliance or legal enforcement",
        "physical deletion or proof of physical erasure",
        "HTGL consensus, ledger anchoring, operational capacity, utility deployment, or execution of represented population N",
    ),
    "physical_validity_scope": (
        "procedural-model constraint validity only: interval continuity, configured units, "
        "meter/DER bounds, aggregate export-production consistency, analytic voltage/loading "
        "bounds, and deterministic trigger integrity"
    ),
}


def _profile_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


SUPPORTED_RELEASE_PROFILE = ReleaseProfile(
    **_PROFILE_CORE,
    profile_sha256=_profile_digest(_PROFILE_CORE),
)


def load_release_profile(profile_id: str) -> ReleaseProfile:
    if profile_id != SUPPORTED_RELEASE_PROFILE.profile_id:
        raise ReleaseProfileError(
            f"unsupported release_profile_id={profile_id!r}; the only publication profile "
            f"is {SUPPORTED_RELEASE_PROFILE.profile_id!r}"
        )
    return SUPPORTED_RELEASE_PROFILE


def validate_resolved_release_profile(resolved: Any) -> ReleaseProfile:
    """Fail closed unless a resolved config is inside the frozen profile."""

    profile = load_release_profile(resolved.output.release_profile_id)
    observed = (
        resolved.physical.backend,
        resolved.physical.backend_version,
        resolved.physical.solver_backend,
    )
    expected = (
        profile.physical_backend,
        profile.physical_backend_version,
        profile.analytic_state_backend,
    )
    if observed != expected:
        raise ReleaseProfileError(
            "release profile requires physical backend/version/analytic-state backend "
            f"{expected!r}, observed {observed!r}; style or external modes are diagnostic-only"
        )
    non_controlled = sorted(
        path
        for path, source_label in resolved.source_labels.items()
        if source_label != profile.required_source_label
    )
    if non_controlled:
        raise ReleaseProfileError(
            "release profile permits controlled_synthetic provenance only; non-controlled "
            f"source labels occur at {non_controlled[:16]}"
        )
    return profile
