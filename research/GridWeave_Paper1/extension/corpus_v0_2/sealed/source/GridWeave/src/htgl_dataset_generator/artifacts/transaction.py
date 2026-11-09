"""Generator-owned staging, recovery, collision, and atomic promotion."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
from typing import Any

from htgl_dataset_generator._atomic import atomic_replace

from .canonical import atomic_write_bytes, canonical_json_bytes, domain_sha256, fsync_directory
from .models import ArtifactCollisionError, ArtifactCompilerError


OWNER_MARKER = ".htgl-generator-owned.json"
OWNER_FORMAT = "htgl.dataset-generator.release-owner.v1"
RECOVERY_FORMAT = "htgl.dataset-generator.recovery.v1"
BUNDLE_ACCESS_CLASSES = ("public", "evaluator_only", "restricted")


class ReleaseTransaction:
    """One deterministic staging transaction with verified owned-tree operations."""

    def __init__(
        self,
        output_root: Path,
        *,
        run_id: str,
        config_sha256: str,
        contract_fingerprint: str,
        collision_policy: str,
    ) -> None:
        if collision_policy not in {"fail", "replace_owned", "reuse_identical"}:
            raise ValueError(
                "collision_policy must be fail, replace_owned, or reuse_identical"
            )
        self.output_root = output_root.resolve()
        self.run_id = run_id
        self.config_sha256 = config_sha256
        self.contract_fingerprint = contract_fingerprint
        self.collision_policy = collision_policy
        self.transaction_id = domain_sha256(
            "release-transaction-id",
            {
                "run_id": run_id,
                "config_sha256": config_sha256,
                "contract_fingerprint": contract_fingerprint,
            },
        )[:24]
        safe_run = _safe_release_name(run_id)
        self.target = self.output_root / f"run_{safe_run}"
        self.staging = self.output_root / f".{safe_run}.staging.{self.transaction_id}"
        self.backup = self.output_root / f".{safe_run}.backup.{self.transaction_id}"
        self.recovery_path = self.output_root / f".{safe_run}.recovery.{self.transaction_id}.json"
        self.lock_path = self.output_root / f".{safe_run}.publication.lock"
        self._phases: list[dict[str, Any]] = []
        self._lock_owned = False

    def begin(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        self._acquire_lock()
        try:
            if self.staging.exists():
                _remove_current_staging(
                    self.staging,
                    self._expected_owner(target_kind="staging"),
                    self._expected_owner(target_kind="release"),
                )
            if self.backup.exists():
                backup_owner = _verify_owned_release(self.backup, self.run_id)
                if not self.target.exists():
                    atomic_replace(self.backup, self.target)
                    fsync_directory(self.output_root)
                else:
                    _remove_owned_tree(self.backup, backup_owner)
            self.staging.mkdir()
            atomic_write_bytes(
                self.staging / OWNER_MARKER,
                canonical_json_bytes(self._expected_owner(target_kind="staging")),
            )
            self.record_phase("staging_created")
        except Exception:
            self.release_lock()
            raise

    def record_phase(self, phase: str, **details: Any) -> None:
        entry = {"sequence": len(self._phases), "phase": phase, "details": details}
        self._phases.append(entry)
        payload = {
            "format": RECOVERY_FORMAT,
            "transaction_id": self.transaction_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "target": self.target.name,
            "staging": self.staging.name,
            "phases": self._phases,
        }
        atomic_write_bytes(self.recovery_path, canonical_json_bytes(payload))

    def recovery_snapshot(self) -> dict[str, Any]:
        return {
            "format": RECOVERY_FORMAT,
            "transaction_id": self.transaction_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "target": self.target.name,
            "phases": tuple(self._phases),
            "operational_log_authority": False,
        }

    def seal_owner_marker(self) -> None:
        atomic_write_bytes(
            self.staging / OWNER_MARKER,
            canonical_json_bytes(self._expected_owner(target_kind="release")),
        )

    def promote(self, expected_release_byte_digest: str) -> bool:
        """Promote staging and return True only when an identical release was reused."""

        if not self.staging.exists():
            raise ArtifactCompilerError("staging directory disappeared before promotion")
        if self.target.exists():
            if self.collision_policy == "fail":
                raise ArtifactCollisionError(
                    f"release target already exists: {self.target}; choose reuse_identical or replace_owned explicitly"
                )
            existing_owner = _verify_owned_release(self.target, self.run_id)
            if self.collision_policy == "reuse_identical":
                existing_manifest = _read_json(self.target / "manifest.json")
                existing_digest = str(existing_manifest.get("release_byte_digest", ""))
                if existing_digest != expected_release_byte_digest:
                    raise ArtifactCollisionError(
                        "existing generator-owned release is not byte-identical to the staged release"
                    )
                _remove_owned_tree(self.staging, self._expected_owner(target_kind="release"))
                self.record_phase("identical_release_reused")
                self.recovery_path.unlink(missing_ok=True)
                self.release_lock()
                return True
            atomic_replace(self.target, self.backup)
            fsync_directory(self.output_root)
            self.record_phase("existing_release_backed_up")
        try:
            atomic_replace(self.staging, self.target)
            fsync_directory(self.output_root)
            self.record_phase("release_promoted")
        except Exception as exc:
            if self.backup.exists() and not self.target.exists():
                atomic_replace(self.backup, self.target)
                fsync_directory(self.output_root)
                self.record_phase("previous_release_restored")
            raise ArtifactCompilerError(f"atomic release promotion failed: {exc}") from exc
        if self.backup.exists():
            _remove_owned_tree(self.backup, existing_owner)
        self.recovery_path.unlink(missing_ok=True)
        self.release_lock()
        return False

    def release_lock(self) -> None:
        if not self._lock_owned:
            return
        try:
            observed = _read_json(self.lock_path)
            expected = self._lock_payload()
            if observed != expected:
                raise ArtifactCollisionError(
                    f"publication lock ownership changed unexpectedly: {self.lock_path}"
                )
            self.lock_path.unlink()
        finally:
            self._lock_owned = False

    def _acquire_lock(self) -> None:
        payload = canonical_json_bytes(self._lock_payload())
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
        except FileExistsError as exc:
            raise ArtifactCollisionError(
                f"another publication transaction or unrecovered lock exists: {self.lock_path}"
            ) from exc
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._lock_owned = True

    def _lock_payload(self) -> dict[str, Any]:
        return {
            "format": "htgl.dataset-generator.publication-lock.v1",
            "transaction_id": self.transaction_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
        }

    def _expected_owner(self, *, target_kind: str) -> dict[str, Any]:
        return {
            "format": OWNER_FORMAT,
            "owner": "htgl_dataset_generator",
            "target_kind": target_kind,
            "transaction_id": self.transaction_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "contract_fingerprint": self.contract_fingerprint,
        }


class ReleaseBundleSetTransaction:
    """Atomic three-bundle publication transaction with rollback on partial promotion."""

    def __init__(
        self,
        output_root: Path,
        *,
        run_id: str,
        config_sha256: str,
        contract_fingerprint: str,
        collision_policy: str,
    ) -> None:
        if collision_policy not in {"fail", "replace_owned", "reuse_identical"}:
            raise ValueError(
                "collision_policy must be fail, replace_owned, or reuse_identical"
            )
        self.output_root = output_root.resolve()
        self.run_id = run_id
        self.config_sha256 = config_sha256
        self.contract_fingerprint = contract_fingerprint
        self.collision_policy = collision_policy
        self.bundle_set_id = domain_sha256(
            "release-bundle-set-id-v1",
            {
                "run_id": run_id,
                "config_sha256": config_sha256,
                "contract_fingerprint": contract_fingerprint,
            },
        )
        self.transaction_id = self.bundle_set_id[:24]
        path_token = self.transaction_id[:12]
        safe_run = _safe_release_name(run_id)
        self._safe_run = safe_run
        # Keep transaction-only prefixes short enough for deep Parquet partitions on
        # Windows without changing any final artifact or release path.
        self.staging_root = self.output_root / f".b-{path_token}"
        self.staging = self.staging_root / "w"
        self.targets = {
            access: self.output_root
            / f"run_{safe_run}-{access.replace('_', '-')}"
            for access in BUNDLE_ACCESS_CLASSES
        }
        self.backups = {
            access: self.output_root
            / f".r-{access[0]}-{path_token}"
            for access in BUNDLE_ACCESS_CLASSES
        }
        self.recovery_path = (
            self.output_root
            / f".htgl-bs.recovery.{self.transaction_id}.json"
        )
        self.lock_path = self.output_root / f".{safe_run}.publication.lock"
        self._phases: list[dict[str, Any]] = []
        self._lock_owned = False

    def begin(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        self._acquire_lock()
        try:
            if self.staging_root.exists():
                _verify_owner(
                    self.staging_root,
                    self._bundle_set_owner("staging_bundle_set"),
                )
                shutil.rmtree(self.staging_root)
            for access, backup in self.backups.items():
                if not backup.exists():
                    continue
                owner = _verify_owned_bundle(backup, self.run_id, access)
                target = self.targets[access]
                if not target.exists():
                    atomic_replace(backup, target)
                    fsync_directory(self.output_root)
                else:
                    _remove_owned_tree(backup, owner)
            self.staging_root.mkdir()
            atomic_write_bytes(
                self.staging_root / OWNER_MARKER,
                canonical_json_bytes(self._bundle_set_owner("staging_bundle_set")),
            )
            self.staging.mkdir()
            self.record_phase("bundle_set_staging_created")
        except Exception:
            self.release_lock()
            raise

    def bundle_staging(self, access_class: str) -> Path:
        if access_class not in BUNDLE_ACCESS_CLASSES:
            raise ValueError(f"unknown bundle access class {access_class!r}")
        path = self.staging_root / f"b{access_class[0]}"
        path.mkdir(exist_ok=True)
        return path

    def seal_bundle_owner_marker(self, access_class: str) -> None:
        atomic_write_bytes(
            self.bundle_staging(access_class) / OWNER_MARKER,
            canonical_json_bytes(self._bundle_owner(access_class)),
        )

    def record_phase(self, phase: str, **details: Any) -> None:
        self._phases.append(
            {"sequence": len(self._phases), "phase": phase, "details": details}
        )
        atomic_write_bytes(
            self.recovery_path,
            canonical_json_bytes(self.recovery_snapshot()),
        )

    def recovery_snapshot(self) -> dict[str, Any]:
        return {
            "format": RECOVERY_FORMAT,
            "transaction_id": self.transaction_id,
            "bundle_set_id": self.bundle_set_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "targets": {
                key: value.name for key, value in sorted(self.targets.items())
            },
            "phases": tuple(self._phases),
            "operational_log_authority": False,
        }

    def promote(self, expected_byte_digests: Mapping[str, str]) -> bool:
        if set(expected_byte_digests) != set(BUNDLE_ACCESS_CLASSES):
            raise ArtifactCompilerError(
                "bundle promotion requires byte digests for all access classes"
            )
        existing = {
            access: target.exists() for access, target in self.targets.items()
        }
        if self.collision_policy == "fail" and any(existing.values()):
            raise ArtifactCollisionError(
                "release bundle target already exists: "
                f"{[str(self.targets[key]) for key, value in existing.items() if value]}"
            )
        if self.collision_policy == "reuse_identical" and any(existing.values()):
            if not all(existing.values()):
                raise ArtifactCollisionError(
                    "cannot reuse a partial release bundle set"
                )
            for access, target in self.targets.items():
                _verify_owned_bundle(target, self.run_id, access)
                manifest = _read_json(target / "manifest.json")
                if manifest.get("release_byte_digest") != expected_byte_digests[access]:
                    raise ArtifactCollisionError(
                        f"existing {access} bundle is not byte-identical"
                    )
            _verify_owner(
                self.staging_root,
                self._bundle_set_owner("staging_bundle_set"),
            )
            shutil.rmtree(self.staging_root)
            self.record_phase("identical_bundle_set_reused")
            self.recovery_path.unlink(missing_ok=True)
            self.release_lock()
            return True

        backup_owners: dict[str, dict[str, Any]] = {}
        if self.collision_policy == "replace_owned":
            for access, target in self.targets.items():
                if target.exists():
                    backup_owners[access] = _verify_owned_bundle(
                        target, self.run_id, access
                    )
            for access in BUNDLE_ACCESS_CLASSES:
                if access not in backup_owners:
                    continue
                atomic_replace(self.targets[access], self.backups[access])
            if backup_owners:
                fsync_directory(self.output_root)
                self.record_phase("existing_bundle_set_backed_up")

        promoted: list[str] = []
        try:
            for access in BUNDLE_ACCESS_CLASSES:
                staged = self.bundle_staging(access)
                _verify_owner(staged, self._bundle_owner(access))
                atomic_replace(staged, self.targets[access])
                promoted.append(access)
            fsync_directory(self.output_root)
        except Exception as exc:
            for access in reversed(promoted):
                if self.targets[access].exists():
                    atomic_replace(
                        self.targets[access], self.bundle_staging(access)
                    )
            for access in BUNDLE_ACCESS_CLASSES:
                backup = self.backups[access]
                if backup.exists() and not self.targets[access].exists():
                    atomic_replace(backup, self.targets[access])
            fsync_directory(self.output_root)
            raise ArtifactCompilerError(
                f"atomic release bundle-set promotion failed: {exc}"
            ) from exc

        for access, owner in backup_owners.items():
            if self.backups[access].exists():
                _remove_owned_tree(self.backups[access], owner)
        _verify_owner(
            self.staging_root,
            self._bundle_set_owner("staging_bundle_set"),
        )
        shutil.rmtree(self.staging_root)
        self.record_phase("release_bundle_set_promoted")
        self.recovery_path.unlink(missing_ok=True)
        self.release_lock()
        return False

    def abort(self) -> None:
        self.release_lock()

    def release_lock(self) -> None:
        if not self._lock_owned:
            return
        try:
            observed = _read_json(self.lock_path)
            if observed != self._lock_payload():
                raise ArtifactCollisionError(
                    f"publication lock ownership changed unexpectedly: {self.lock_path}"
                )
            self.lock_path.unlink()
        finally:
            self._lock_owned = False

    def _acquire_lock(self) -> None:
        payload = canonical_json_bytes(self._lock_payload())
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
        except FileExistsError as exc:
            raise ArtifactCollisionError(
                f"another publication transaction or unrecovered lock exists: {self.lock_path}"
            ) from exc
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._lock_owned = True

    def _lock_payload(self) -> dict[str, Any]:
        return {
            "format": "htgl.dataset-generator.publication-lock.v1",
            "transaction_id": self.transaction_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
        }

    def _bundle_set_owner(self, target_kind: str) -> dict[str, Any]:
        return {
            "format": OWNER_FORMAT,
            "owner": "htgl_dataset_generator",
            "target_kind": target_kind,
            "transaction_id": self.transaction_id,
            "bundle_set_id": self.bundle_set_id,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "contract_fingerprint": self.contract_fingerprint,
        }

    def _bundle_owner(self, access_class: str) -> dict[str, Any]:
        return {
            "format": OWNER_FORMAT,
            "owner": "htgl_dataset_generator",
            "target_kind": "release",
            "transaction_id": self.transaction_id,
            "bundle_set_id": self.bundle_set_id,
            "bundle_access_class": access_class,
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "contract_fingerprint": self.contract_fingerprint,
        }


def _safe_release_name(value: str) -> str:
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise ValueError(
            "run_id must use only ASCII letters, digits, period, underscore, or hyphen for release paths"
        )
    if value in {".", ".."}:
        raise ValueError("run_id cannot be a traversal token")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ArtifactCollisionError(f"cannot read generator ownership metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactCollisionError(f"ownership metadata {path} is not a JSON object")
    return value


def _verify_owner(root: Path, expected: dict[str, Any]) -> None:
    marker = root / OWNER_MARKER
    if not marker.is_file():
        raise ArtifactCollisionError(
            f"refusing destructive replacement because {root} lacks {OWNER_MARKER}"
        )
    observed = _read_json(marker)
    if observed != expected:
        raise ArtifactCollisionError(
            f"refusing destructive replacement because ownership marker for {root} does not match this transaction"
        )


def _verify_owned_release(root: Path, run_id: str) -> dict[str, Any]:
    marker = root / OWNER_MARKER
    if not marker.is_file():
        raise ArtifactCollisionError(
            f"refusing destructive replacement because {root} lacks {OWNER_MARKER}"
        )
    observed = _read_json(marker)
    required = {
        "format": OWNER_FORMAT,
        "owner": "htgl_dataset_generator",
        "target_kind": "release",
        "run_id": run_id,
    }
    if any(observed.get(key) != value for key, value in required.items()):
        raise ArtifactCollisionError(
            f"refusing destructive replacement because {root} is not a generator-owned release for run {run_id}"
        )
    for key in ("transaction_id", "config_sha256", "contract_fingerprint"):
        if not isinstance(observed.get(key), str) or not observed[key]:
            raise ArtifactCollisionError(
                f"generator ownership marker for {root} lacks {key}"
            )
    return observed


def _verify_owned_bundle(
    root: Path,
    run_id: str,
    access_class: str,
) -> dict[str, Any]:
    observed = _verify_owned_release(root, run_id)
    if observed.get("bundle_access_class") != access_class:
        raise ArtifactCollisionError(
            f"refusing bundle operation because {root} is not the {access_class} bundle"
        )
    if not isinstance(observed.get("bundle_set_id"), str) or not observed[
        "bundle_set_id"
    ]:
        raise ArtifactCollisionError(
            f"generator ownership marker for {root} lacks bundle_set_id"
        )
    return observed


def _remove_owned_tree(root: Path, expected: dict[str, Any]) -> None:
    resolved_root = root.resolve()
    resolved_parent = root.parent.resolve()
    if resolved_root.parent != resolved_parent or resolved_root == resolved_parent:
        raise ArtifactCollisionError(f"refusing unsafe owned-tree removal for {root}")
    _verify_owner(root, expected)
    shutil.rmtree(root)


def _remove_current_staging(
    root: Path,
    staging_owner: dict[str, Any],
    sealed_owner: dict[str, Any],
) -> None:
    marker = root / OWNER_MARKER
    if not marker.is_file():
        raise ArtifactCollisionError(
            f"refusing stale staging cleanup because {root} lacks {OWNER_MARKER}"
        )
    observed = _read_json(marker)
    if observed not in (staging_owner, sealed_owner):
        raise ArtifactCollisionError(
            f"refusing stale staging cleanup because ownership does not match the current transaction"
        )
    resolved_root = root.resolve()
    if resolved_root.parent != root.parent.resolve():
        raise ArtifactCollisionError(f"refusing unsafe stale staging cleanup for {root}")
    shutil.rmtree(root)
