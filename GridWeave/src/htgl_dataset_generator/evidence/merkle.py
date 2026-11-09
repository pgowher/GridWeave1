"""Domain-separated deterministic Merkle/transparency inclusion fixtures."""

from __future__ import annotations

import hashlib
from typing import Mapping, Sequence

from htgl_dataset_generator.seeds import content_id

from .fixtures import MerkleProofStep, SyntheticAnchorFixture
from .profiles import AnchorProfile


def build_merkle_anchor(
    leaves_by_receipt_id: Mapping[str, str],
    *,
    profile: AnchorProfile,
    scenario_id: str,
    replicate_id: int,
) -> tuple[SyntheticAnchorFixture, Mapping[str, tuple[MerkleProofStep, ...]]]:
    """Build an order-stable tree and an inclusion path for every receipt."""

    if not leaves_by_receipt_id:
        raise ValueError("Merkle anchor requires at least one receipt leaf")
    ordered = tuple(sorted(leaves_by_receipt_id.items()))
    if len({receipt_id for receipt_id, _ in ordered}) != len(ordered):
        raise ValueError("duplicate Merkle receipt IDs")
    level = [(_leaf_hash(bytes.fromhex(digest), profile), (receipt_id,)) for receipt_id, digest in ordered]
    paths: dict[str, list[MerkleProofStep]] = {receipt_id: [] for receipt_id, _ in ordered}
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        next_level: list[tuple[bytes, tuple[str, ...]]] = []
        for index in range(0, len(level), 2):
            left_hash, left_ids = level[index]
            right_hash, right_ids = level[index + 1]
            if left_ids == right_ids:
                for receipt_id in left_ids:
                    paths[receipt_id].append(MerkleProofStep(right_hash.hex(), "right"))
                parent_ids = left_ids
            else:
                for receipt_id in left_ids:
                    paths[receipt_id].append(MerkleProofStep(right_hash.hex(), "right"))
                for receipt_id in right_ids:
                    paths[receipt_id].append(MerkleProofStep(left_hash.hex(), "left"))
                parent_ids = left_ids + right_ids
            next_level.append((_node_hash(left_hash, right_hash, profile), parent_ids))
        level = next_level
    root = level[0][0].hex()
    anchor_id = content_id(
        "synthetic_merkle_anchor",
        {
            "anchor_profile_id": profile.anchor_profile_id,
            "leaf_count": len(ordered),
            "replicate_id": replicate_id,
            "root_digest": root,
            "scenario_id": scenario_id,
        },
    )
    anchor = SyntheticAnchorFixture(
        anchor_id=anchor_id,
        anchor_profile_id=profile.anchor_profile_id,
        algorithm=profile.algorithm,
        root_digest=root,
        leaf_count=len(ordered),
    )
    return anchor, {key: tuple(value) for key, value in sorted(paths.items())}


def verify_merkle_path(
    digest_hex: str,
    path: Sequence[MerkleProofStep],
    *,
    root_digest: str,
    profile: AnchorProfile,
) -> bool:
    try:
        current = _leaf_hash(bytes.fromhex(digest_hex), profile)
        for step in path:
            sibling = bytes.fromhex(step.sibling_digest)
            if len(sibling) != 32:
                return False
            if step.sibling_position == "left":
                current = _node_hash(sibling, current, profile)
            elif step.sibling_position == "right":
                current = _node_hash(current, sibling, profile)
            else:
                return False
        return current.hex() == root_digest
    except ValueError:
        return False


def _leaf_hash(digest: bytes, profile: AnchorProfile) -> bytes:
    if len(digest) != 32:
        raise ValueError("Merkle leaf digest must be 32 bytes")
    return hashlib.sha256(profile.leaf_domain.encode("utf-8") + b"\x00" + digest).digest()


def _node_hash(left: bytes, right: bytes, profile: AnchorProfile) -> bytes:
    return hashlib.sha256(profile.node_domain.encode("utf-8") + b"\x00" + left + right).digest()
