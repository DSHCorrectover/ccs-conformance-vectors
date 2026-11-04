#!/usr/bin/env python3
"""Build the BoundaryAttest-native receipt for paired fixture 01-deny."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent.parent / "event.json"
KEY_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
MAX_SAFE_INTEGER = 2**53 - 1
FIXTURE_KEY_LABEL = b"BoundaryAttest paired fixture 01-deny TEST-ONLY Ed25519 key v1"


def check_canonical_subset(value: Any, path: str = "value") -> None:
    """Restrict values to the portable subset used by the Python v0.1 example."""
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not KEY_NAME.fullmatch(key):
                raise ValueError(
                    f"{path}: keys must be lowercase ASCII snake_case: {key!r}"
                )
            check_canonical_subset(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_canonical_subset(child, f"{path}[{index}]")
    elif isinstance(value, bool) or value is None or isinstance(value, str):
        return
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer is outside JavaScript's safe range")
    elif isinstance(value, float):
        raise ValueError(f"{path}: floating-point values are unsupported")
    else:
        raise ValueError(f"{path}: unsupported JSON value")


def stable_json_bytes(value: Any) -> bytes:
    check_canonical_subset(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(stable_json_bytes(value)).hexdigest()


def main() -> None:
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    args_digest = sha256_hex(event["request"]["arguments"])
    event_digest = sha256_hex(event)

    claim = {
        "receipt_version": "0.1",
        "receipt_role": "server_attested",
        "event_id": event["event_id"],
        "timestamp": event["timestamps"]["evidence_exported_at"],
        "action_type": "gate.decision.evidence_exported",
        "status": "denied",
        "action": f'{event["request"]["tool"]}.admission_decision',
        "tool_name": event["request"]["tool"],
        "tool_call_id": event["request"]["tool_call_id"],
        "args_digest": args_digest,
        "input_hash": f"sha256:{args_digest}",
        "policy_ref": event["policy"]["policy_ref"],
        "policy_version": event["policy"]["policy_version"],
        "policy_digest": event["policy"]["policy_digest"],
        "policy_digest_algorithm": event["policy"]["policy_digest_algorithm"],
        "verdict": event["decision"]["verdict"],
        "reason_code": event["decision"]["reason_code"],
        "reason": event["decision"]["reason"],
        "executed": event["execution"]["executed"],
        "requested_at": event["timestamps"]["requested_at"],
        "decided_at": event["timestamps"]["decided_at"],
        "decided_by": event["decision"]["decided_by"],
        "gate_version": event["decision"]["gate_version"],
        "agent_id": event["actor"]["agent_id"],
        "agent_version": event["actor"]["agent_version"],
        "run_id": event["actor"]["run_id"],
        "event_digest": event_digest,
        "event_digest_algorithm": "sha256",
        "target_ref": f'tool-call:{event["request"]["tool_call_id"]}',
        "trace_ref": event["actor"]["run_id"],
        "output_hash": None,
    }

    # Deterministic fixture-only material: the published label is hashed to a
    # 32-byte Ed25519 seed. No private-key file is created or required.
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(FIXTURE_KEY_LABEL).digest()
    )
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    receipt = {
        "claim": claim,
        "signature": base64.b64encode(private_key.sign(stable_json_bytes(claim))).decode(
            "ascii"
        ),
        "public_key_id": "sha256:" + hashlib.sha256(public_der).hexdigest(),
    }

    (HERE / "public-key.pem").write_bytes(public_pem)
    (HERE / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f'wrote {HERE / "receipt.json"}')
    print(f'wrote {HERE / "public-key.pem"}')
    print(f"args_digest={args_digest}")
    print(f"event_digest={event_digest}")
    print(f"public_key_id={receipt['public_key_id']}")


if __name__ == "__main__":
    main()
