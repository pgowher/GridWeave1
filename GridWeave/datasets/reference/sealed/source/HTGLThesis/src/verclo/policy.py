"""Schema-backed modular policy profiles; no legal parameter is hard-coded in services."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from jsonschema import Draft202012Validator

from .canonical import commitment


POLICY_ROOT = Path(__file__).resolve().parents[1] / "policy"


@dataclass(frozen=True)
class PolicyRule:
    deadline_hours: int
    minimum_evidence_grade: str
    permitted_dispositions: tuple[str, ...]


@dataclass(frozen=True)
class PolicyOverride:
    override_id: str
    asset_kinds: tuple[str, ...]
    replica_classes: tuple[str, ...]
    rule: PolicyRule


@dataclass(frozen=True)
class PolicyProfile:
    profile_id: str
    version: str
    authorization_basis: str
    applicable_asset_kinds: tuple[str, ...]
    applicable_replica_classes: tuple[str, ...]
    default_rule: PolicyRule
    overrides: tuple[PolicyOverride, ...]
    exception_authority_ids: tuple[str, ...]
    early_closure_allowed: bool
    sha256: str

    def applies(self, asset_kind: str, replica_class: str) -> bool:
        asset_applies = "*" in self.applicable_asset_kinds or asset_kind in self.applicable_asset_kinds
        return asset_applies and replica_class in self.applicable_replica_classes

    def resolve_rule(self, asset_kind: str, replica_class: str) -> PolicyRule:
        matches: list[tuple[int, PolicyOverride]] = []
        for override in self.overrides:
            asset_match = asset_kind in override.asset_kinds or "*" in override.asset_kinds
            replica_match = replica_class in override.replica_classes or "*" in override.replica_classes
            if asset_match and replica_match:
                specificity = int("*" not in override.asset_kinds) + int("*" not in override.replica_classes)
                matches.append((specificity, override))
        if not matches:
            return self.default_rule
        best = max(score for score, _ in matches)
        selected = [row for score, row in matches if score == best]
        if len(selected) != 1:
            raise ValueError(f"ambiguous policy overrides for {asset_kind}/{replica_class}")
        return selected[0].rule


def _rule(payload: Mapping[str, object]) -> PolicyRule:
    return PolicyRule(
        deadline_hours=int(payload["deadline_hours"]),
        minimum_evidence_grade=str(payload["minimum_evidence_grade"]),
        permitted_dispositions=tuple(sorted(map(str, payload["permitted_dispositions"]))),
    )


class PolicyRegistry:
    def __init__(self, profiles: Mapping[str, PolicyProfile]) -> None:
        self._profiles = dict(profiles)

    @classmethod
    def load(cls, directory: str | Path | None = None) -> "PolicyRegistry":
        root = Path(directory) if directory is not None else POLICY_ROOT / "profiles"
        schema = json.loads((POLICY_ROOT / "verclo_policy_profile_v1.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        profiles: dict[str, PolicyProfile] = {}
        for path in sorted(root.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            validator.validate(payload)
            profile_id = str(payload["profile_id"])
            if profile_id in profiles:
                raise ValueError(f"duplicate policy profile: {profile_id}")
            overrides = tuple(
                PolicyOverride(
                    override_id=str(row["override_id"]),
                    asset_kinds=tuple(map(str, row["asset_kinds"])),
                    replica_classes=tuple(map(str, row["replica_classes"])),
                    rule=_rule(row["rule"]),
                )
                for row in payload["overrides"]
            )
            profiles[profile_id] = PolicyProfile(
                profile_id=profile_id,
                version=str(payload["version"]),
                authorization_basis=str(payload["authorization_basis"]),
                applicable_asset_kinds=tuple(map(str, payload["applicable_asset_kinds"])),
                applicable_replica_classes=tuple(map(str, payload["applicable_replica_classes"])),
                default_rule=_rule(payload["default_rule"]),
                overrides=overrides,
                exception_authority_ids=tuple(sorted(map(str, payload["exception_authority_ids"]))),
                early_closure_allowed=bool(payload["early_closure_allowed"]),
                sha256=commitment("verclo-policy-profile-v1", payload),
            )
        if not profiles:
            raise ValueError("policy registry is empty")
        return cls(profiles)

    def get(self, profile_id: str) -> PolicyProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise KeyError(f"unknown policy profile: {profile_id}") from exc

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._profiles))
