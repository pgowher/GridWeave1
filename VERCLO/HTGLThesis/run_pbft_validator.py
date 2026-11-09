#!/usr/bin/env python3
"""Run one durable PBFT validator from a generated deployment config."""

from __future__ import annotations

import argparse
import base64
import json
import signal
import threading
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evidence import BackendValidation
from proof import serve_pbft_validator


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    raw_decision = dict(config["decision"])
    expires = raw_decision.pop("mechanism_expires_at", None)
    decision = BackendValidation(
        "p13-remote-validator",
        mechanism_expires_at=datetime.fromisoformat(expires) if expires else None,
        **raw_decision,
    )
    state_path = Path(config["state_path"])
    if not state_path.is_absolute():
        state_path = config_path.parent / state_path
    service = serve_pbft_validator(
        config["validator_id"],
        Ed25519PrivateKey.from_private_bytes(decode(config["private_key"])),
        {key: decode(value) for key, value in config["public_keys"].items()},
        config["membership_epoch"],
        decision,
        host=config.get("bind_host", "127.0.0.1"),
        port=int(config.get("bind_port", 8443)),
        state_path=state_path,
    )
    stopped = threading.Event()

    def stop(*_: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    service.start()
    print(f"{config['validator_id']} listening on {config.get('bind_host', '127.0.0.1')}:{config.get('bind_port', 8443)}", flush=True)
    stopped.wait()
    service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
