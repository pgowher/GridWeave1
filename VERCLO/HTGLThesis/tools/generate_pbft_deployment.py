#!/usr/bin/env python3
"""Generate per-host PBFT node configs and a public client topology."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--epoch", default="P13-TPDS-EPOCH-1")
    parser.add_argument("--transport", default="WireGuard overlay HTTP")
    args = parser.parse_args()
    size = len(args.hosts)
    if size < 4 or (size - 1) % 3 != 0:
        raise SystemExit("host count must be 3f+1 (4, 7, 10, ...)")
    args.output.mkdir(parents=True, exist_ok=False)
    ids = tuple(f"VALIDATOR-{index:02d}" for index in range(1, size + 1))
    keys = {validator_id: Ed25519PrivateKey.generate() for validator_id in ids}
    public_keys = {
        validator_id: encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        for validator_id, key in keys.items()
    }
    endpoints = {
        validator_id: f"http://{host}:{args.port}"
        for validator_id, host in zip(ids, args.hosts, strict=True)
    }
    decision = {
        "anchor_valid": True,
        "ordering_support_valid": True,
        "authenticator_valid": True,
        "credential_valid_at_event": True,
        "mechanism_present": False,
        "mechanism_valid": False,
        "mechanism_expires_at": None,
    }
    for validator_id in ids:
        private = keys[validator_id].private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        node_dir = args.output / validator_id
        node_dir.mkdir()
        config = {
            "validator_id": validator_id,
            "membership_epoch": args.epoch,
            "bind_host": "0.0.0.0",
            "bind_port": args.port,
            "private_key": encode(private),
            "public_keys": public_keys,
            "decision": decision,
            "state_path": "data/replica.sqlite3",
        }
        config_path = node_dir / "node.json"
        config_path.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(config_path, 0o600)
    topology = {
        "study_id": "P13-TPDS-EXTENSION-REMOTE-v1",
        "topology_label": "SET-ME",
        "transport": args.transport,
        "membership_epoch": args.epoch,
        "endpoints": endpoints,
        "public_keys": public_keys,
        "client_state_path": "p13-client.sqlite3",
    }
    (args.output / "topology.json").write_text(
        json.dumps(topology, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

