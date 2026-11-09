"""Strict receipt, synthetic-key, anchor, and adversarial fixture profiles."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract


BUNDLE_FORMAT = "htgl.evidence.receipt-profiles.v1"
DEFAULT_BUNDLE_RELATIVE_PATH = Path("evidence") / "receipt_profiles_v1.json"
CANONICALIZATION_PROFILE = "HTGL-CANONICAL-TLV-UTC-US-v1"
SYNTHETIC_KEY_PROFILE = "KEYS-SYNTHETIC-NO-SECRETS-v1"
PROOF_LIMIT_STATEMENT = (
    "Evidence fixtures evaluate model-level verification assumptions and do not prove physical deletion."
)
PRIMITIVES = frozenset({"digest", "hmac", "signature", "merkle_inclusion"})
ADVERSARIAL_CASE_TYPES = (
    "invalid",
    "late",
    "malformed",
    "contradictory",
    "forged_under_synthetic_key",
    "incomplete",
    "missing_dependency",
)
EXPECTED_ALGORITHM = {
    "digest": "SHA-256",
    "hmac": "HMAC-SHA256-SYNTHETIC",
    "signature": "Ed25519-SYNTHETIC",
    "merkle_inclusion": "HTGL-MERKLE-SHA256-v1",
}


class ReceiptProfileError(ValueError):
    """Raised when a receipt profile bundle is incomplete, unpinned, or contradictory."""


@dataclass(frozen=True)
class ReceiptProfile:
    evidence_type: str
    profile_id: str
    primitive: str
    algorithm: str
    domain: str
    requires_key: bool
    requires_anchor: bool


@dataclass(frozen=True)
class AnchorProfile:
    anchor_profile_id: str
    algorithm: str
    leaf_domain: str
    node_domain: str
    odd_leaf_rule: str


@dataclass(frozen=True)
class ReceiptProfileBundle:
    bundle_format: str
    bundle_id: str
    version: str
    canonicalization_profile_id: str
    synthetic_key_profile_id: str
    proof_limit_statement: str
    adversarial_case_types: tuple[str, ...]
    anchor_profiles: tuple[AnchorProfile, ...]
    profiles: tuple[ReceiptProfile, ...]
    ml_removal_profiles: tuple[str, ...]
    bundle_sha256: str

    def profile(self, evidence_type: str) -> ReceiptProfile:
        for item in self.profiles:
            if item.evidence_type == evidence_type:
                return item
        raise ReceiptProfileError(f"no receipt profile for evidence_type={evidence_type!r}")

    def anchor_profile(self, anchor_profile_id: str) -> AnchorProfile:
        for item in self.anchor_profiles:
            if item.anchor_profile_id == anchor_profile_id:
                return item
        raise ReceiptProfileError(f"unknown anchor_profile_id={anchor_profile_id!r}")


def load_receipt_profile_bundle(
    resolved: ResolvedConfig,
    path: Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> ReceiptProfileBundle:
    """Load and fail-closed validate the exact configured receipt profile registry."""

    schema_contract = contract if contract is not None else load_contract()
    bundle_path = path.resolve() if path is not None else _repo_root() / DEFAULT_BUNDLE_RELATIVE_PATH
    try:
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReceiptProfileError(f"receipt profile bundle not found: {bundle_path}") from exc
    except json.JSONDecodeError as exc:
        raise ReceiptProfileError(f"invalid receipt profile JSON {bundle_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ReceiptProfileError("receipt profile bundle root must be an object")
    _exact_keys(
        raw,
        {
            "bundle_format",
            "bundle_id",
            "version",
            "canonicalization_profile_id",
            "synthetic_key_profile_id",
            "proof_limit_statement",
            "adversarial_case_types",
            "anchor_profiles",
            "profiles",
            "ml_removal_profiles",
        },
        "receipt profile bundle",
    )
    _require(raw["bundle_format"] == BUNDLE_FORMAT, f"bundle_format must be {BUNDLE_FORMAT}")
    _require(raw["bundle_id"] == resolved.evidence.receipt_profile_bundle_id, "bundle_id does not match config")
    _require(raw["version"] == resolved.evidence.receipt_profile_bundle_version, "bundle version does not match config")
    _require(
        raw["canonicalization_profile_id"] == resolved.evidence.canonicalization_profile_id == CANONICALIZATION_PROFILE,
        "canonicalization profile does not match the supported pinned profile",
    )
    _require(
        raw["synthetic_key_profile_id"] == resolved.evidence.synthetic_key_profile_id == SYNTHETIC_KEY_PROFILE,
        "synthetic key profile does not match the supported pinned profile",
    )
    _require(
        raw["proof_limit_statement"] == resolved.evidence.proof_limit_statement == PROOF_LIMIT_STATEMENT,
        "proof limit statement does not match the model-level evidence boundary",
    )
    case_types = _string_tuple(raw["adversarial_case_types"], "adversarial_case_types", non_empty=True)
    _require(case_types == ADVERSARIAL_CASE_TYPES, "adversarial case registry must preserve the controlled order and complete set")
    raw_anchors = raw["anchor_profiles"]
    if not isinstance(raw_anchors, list) or not raw_anchors:
        raise ReceiptProfileError("anchor_profiles must be a non-empty list")
    anchors = tuple(_load_anchor(item, index) for index, item in enumerate(raw_anchors))
    _unique((item.anchor_profile_id for item in anchors), "anchor profile IDs")
    _require(
        set(item.anchor_profile_id for item in anchors) == set(resolved.evidence.anchor_profiles),
        "anchor profiles must exactly match config",
    )
    raw_profiles = raw["profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ReceiptProfileError("profiles must be a non-empty list")
    profiles = tuple(_load_profile(item, index, schema_contract) for index, item in enumerate(raw_profiles))
    _unique((item.evidence_type for item in profiles), "profile evidence types")
    _unique((item.profile_id for item in profiles), "receipt profile IDs")
    _unique((item.domain for item in profiles), "receipt domains")
    configured_types = set(resolved.evidence.receipt_profiles)
    observed_types = {item.evidence_type for item in profiles}
    _require(observed_types == configured_types, "receipt profiles must exactly match configured evidence types")
    _require(
        observed_types == set(schema_contract.dictionary_values("evidence_type")),
        "receipt profile bundle must cover every contract evidence type",
    )
    ml_profiles = _string_tuple(raw["ml_removal_profiles"], "ml_removal_profiles", non_empty=False)
    _require(
        ml_profiles == resolved.evidence.ml_removal_profile_ids == (),
        "ML removal fixtures are disabled until an explicit model and removal-input contract is pinned",
    )
    bundle_sha256 = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    _require(
        bundle_sha256 == resolved.evidence.receipt_profile_bundle_sha256,
        "receipt profile bundle SHA-256 does not match resolved config: "
        f"expected={resolved.evidence.receipt_profile_bundle_sha256} observed={bundle_sha256}",
    )
    return ReceiptProfileBundle(
        bundle_format=str(raw["bundle_format"]),
        bundle_id=str(raw["bundle_id"]),
        version=str(raw["version"]),
        canonicalization_profile_id=str(raw["canonicalization_profile_id"]),
        synthetic_key_profile_id=str(raw["synthetic_key_profile_id"]),
        proof_limit_statement=str(raw["proof_limit_statement"]),
        adversarial_case_types=case_types,
        anchor_profiles=tuple(sorted(anchors, key=lambda item: item.anchor_profile_id)),
        profiles=tuple(sorted(profiles, key=lambda item: item.evidence_type)),
        ml_removal_profiles=ml_profiles,
        bundle_sha256=bundle_sha256,
    )


def _load_anchor(raw: Any, index: int) -> AnchorProfile:
    if not isinstance(raw, Mapping):
        raise ReceiptProfileError(f"anchor_profiles[{index}] must be an object")
    _exact_keys(raw, {"anchor_profile_id", "algorithm", "leaf_domain", "node_domain", "odd_leaf_rule"}, f"anchor_profiles[{index}]")
    item = AnchorProfile(
        anchor_profile_id=_string(raw["anchor_profile_id"], f"anchor_profiles[{index}].anchor_profile_id"),
        algorithm=_string(raw["algorithm"], f"anchor_profiles[{index}].algorithm"),
        leaf_domain=_string(raw["leaf_domain"], f"anchor_profiles[{index}].leaf_domain"),
        node_domain=_string(raw["node_domain"], f"anchor_profiles[{index}].node_domain"),
        odd_leaf_rule=_string(raw["odd_leaf_rule"], f"anchor_profiles[{index}].odd_leaf_rule"),
    )
    _require(item.algorithm == "HTGL-MERKLE-SHA256-v1", "only the pinned synthetic Merkle algorithm is supported")
    _require(item.odd_leaf_rule == "duplicate_last", "unsupported Merkle odd-leaf rule")
    _require(item.leaf_domain != item.node_domain, "Merkle leaf and node domains must differ")
    return item


def _load_profile(raw: Any, index: int, contract: ContractSpec) -> ReceiptProfile:
    if not isinstance(raw, Mapping):
        raise ReceiptProfileError(f"profiles[{index}] must be an object")
    _exact_keys(raw, {"evidence_type", "profile_id", "primitive", "algorithm", "domain", "requires_key", "requires_anchor"}, f"profiles[{index}]")
    evidence_type = _string(raw["evidence_type"], f"profiles[{index}].evidence_type")
    _require(evidence_type in contract.dictionary_values("evidence_type"), f"unknown evidence_type={evidence_type!r}")
    primitive = _string(raw["primitive"], f"profiles[{index}].primitive")
    _require(primitive in PRIMITIVES, f"unsupported primitive={primitive!r}")
    requires_key = _boolean(raw["requires_key"], f"profiles[{index}].requires_key")
    requires_anchor = _boolean(raw["requires_anchor"], f"profiles[{index}].requires_anchor")
    _require(requires_key == (primitive in {"hmac", "signature"}), f"{evidence_type}: key requirement contradicts primitive")
    _require(requires_anchor == (primitive == "merkle_inclusion"), f"{evidence_type}: anchor requirement contradicts primitive")
    algorithm = _string(raw["algorithm"], f"profiles[{index}].algorithm")
    _require(algorithm == EXPECTED_ALGORITHM[primitive], f"{evidence_type}: algorithm is not pinned for primitive")
    return ReceiptProfile(
        evidence_type=evidence_type,
        profile_id=_string(raw["profile_id"], f"profiles[{index}].profile_id"),
        primitive=primitive,
        algorithm=algorithm,
        domain=_string(raw["domain"], f"profiles[{index}].domain"),
        requires_key=requires_key,
        requires_anchor=requires_anchor,
    )


def _repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in (start, *start.parents):
        if (candidate / "schemas" / "htgl_contract_v1.json").exists():
            return candidate
    raise ReceiptProfileError(f"cannot locate repository root from {start}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReceiptProfileError(f"{label} keys must be {sorted(expected)}, got {sorted(value)}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptProfileError(f"{label} must be a non-empty string")
    return value


def _string_tuple(value: Any, label: str, *, non_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (non_empty and not value):
        raise ReceiptProfileError(f"{label} must be a {'non-empty ' if non_empty else ''}list")
    result = tuple(_string(item, f"{label}[]") for item in value)
    _unique(result, label)
    return result


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ReceiptProfileError(f"{label} must be boolean")
    return value


def _unique(values: Any, label: str) -> None:
    items = tuple(values)
    if len(set(items)) != len(items):
        raise ReceiptProfileError(f"{label} contain duplicates")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptProfileError(message)
