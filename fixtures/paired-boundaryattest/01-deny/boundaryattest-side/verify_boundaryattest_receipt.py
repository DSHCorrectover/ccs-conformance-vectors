#!/usr/bin/env python3
"""Independently verify the BoundaryAttest receipt for paired fixture 01-deny."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent.parent / "event.json"
TOP_LEVEL_FIELDS = {"claim", "signature", "public_key_id"}
REQUIRED_CLAIM_FIELDS = {
    "receipt_version",
    "receipt_role",
    "event_id",
    "timestamp",
    "action_type",
    "status",
}
KEY_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
MAX_SAFE_INTEGER = 2**53 - 1


def check_canonical_subset(value: Any, path: str = "value") -> None:
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


def load_expected_public_key(path: Path) -> tuple[Ed25519PublicKey, bytes]:
    loaded = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("expected public key is not Ed25519")
    der = loaded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return loaded, der


def signature_is_valid(receipt: dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
        public_key.verify(signature, stable_json_bytes(receipt["claim"]))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, binascii.Error):
        return False


def semantic_errors(receipt: dict[str, Any], event: dict[str, Any]) -> list[str]:
    claim = receipt["claim"]
    expected = {
        "event_id": event["event_id"],
        "timestamp": event["timestamps"]["evidence_exported_at"],
        "action_type": "gate.decision.evidence_exported",
        "status": "denied",
        "action": f'{event["request"]["tool"]}.admission_decision',
        "tool_name": event["request"]["tool"],
        "tool_call_id": event["request"]["tool_call_id"],
        "policy_ref": event["policy"]["policy_ref"],
        "policy_version": event["policy"]["policy_version"],
        "policy_digest": event["policy"]["policy_digest"],
        "policy_digest_algorithm": "sha256",
        "verdict": "DENY",
        "reason_code": event["decision"]["reason_code"],
        "reason": event["decision"]["reason"],
        "executed": False,
        "requested_at": event["timestamps"]["requested_at"],
        "decided_at": event["timestamps"]["decided_at"],
        "decided_by": event["decision"]["decided_by"],
        "gate_version": event["decision"]["gate_version"],
        "agent_id": event["actor"]["agent_id"],
        "agent_version": event["actor"]["agent_version"],
        "run_id": event["actor"]["run_id"],
        "event_digest_algorithm": "sha256",
        "target_ref": f'tool-call:{event["request"]["tool_call_id"]}',
        "trace_ref": event["actor"]["run_id"],
        "output_hash": None,
    }
    errors = [
        f"{field} mismatch" for field, value in expected.items() if claim.get(field) != value
    ]
    args_digest = sha256_hex(event["request"]["arguments"])
    if claim.get("args_digest") != args_digest:
        errors.append("args_digest mismatch")
    if claim.get("input_hash") != f"sha256:{args_digest}":
        errors.append("input_hash mismatch")
    if claim.get("event_digest") != sha256_hex(event):
        errors.append("event_digest mismatch")
    policy_text_digest = hashlib.sha256(
        event["policy"]["policy_text"].encode("utf-8")
    ).hexdigest()
    if policy_text_digest != event["policy"]["policy_digest"]:
        errors.append("neutral event policy_digest does not match exact policy_text")
    if claim.get("policy_digest") != policy_text_digest:
        errors.append("claim policy_digest does not match exact policy_text")

    # A denied admission decision must not carry tool-output or success semantics.
    forbidden_truths = (
        claim.get("executed") is not False,
        claim.get("output_hash") is not None,
        claim.get("status") in {"success", "executed", "completed"},
        claim.get("action_type") == event["request"]["tool"],
    )
    if any(forbidden_truths):
        errors.append("claim implies tool execution or a successful execution result")
    return errors


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    receipt = json.loads((HERE / "receipt.json").read_text(encoding="utf-8"))
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    public_key, public_der = load_expected_public_key(HERE / "public-key.pem")

    check("receipt is an object", isinstance(receipt, dict))
    actual_top_level = set(receipt) if isinstance(receipt, dict) else set()
    check(
        "strict three-field top-level envelope",
        actual_top_level == TOP_LEVEL_FIELDS,
        f"fields={sorted(actual_top_level)}",
    )
    claim = receipt.get("claim")
    check("claim is an object", isinstance(claim, dict))
    missing_claim = sorted(REQUIRED_CLAIM_FIELDS - set(claim or {}))
    check("required claim fields present", not missing_claim, f"missing={missing_claim}")
    check("receipt_version is 0.1", claim.get("receipt_version") == "0.1")
    check(
        "receipt_role is server_attested",
        claim.get("receipt_role") == "server_attested",
    )

    expected_key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
    check(
        "expected SPKI-DER public key fingerprint matches public_key_id",
        receipt.get("public_key_id") == expected_key_id,
        expected_key_id,
    )
    check(
        "Ed25519 signature verifies over stableJson claim",
        signature_is_valid(receipt, public_key),
    )

    errors = semantic_errors(receipt, event)
    check("neutral-event semantic bindings", not errors, "; ".join(errors))
    check(
        "policy_digest is SHA-256 of exact UTF-8 policy_text",
        claim.get("policy_digest")
        == hashlib.sha256(event["policy"]["policy_text"].encode("utf-8")).hexdigest(),
        claim.get("policy_digest", ""),
    )
    check(
        "pre-admission denial carries no execution result",
        claim.get("verdict") == "DENY"
        and claim.get("status") == "denied"
        and claim.get("executed") is False
        and claim.get("output_hash") is None,
    )

    tampered_receipt = copy.deepcopy(receipt)
    tampered_receipt["claim"]["status"] = "allowed"
    check(
        "tamper check: changed signed claim fails signature",
        not signature_is_valid(tampered_receipt, public_key),
    )

    tampered_event = copy.deepcopy(event)
    tampered_event["request"]["arguments"]["timeout_seconds"] = 11
    check(
        "tamper check: changed event arguments fail semantic verification",
        "args_digest mismatch" in semantic_errors(receipt, tampered_event),
    )

    width = max(len(name) for name, _, _ in checks)
    failures = 0
    for name, ok, detail in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name.ljust(width)}  {detail if not ok else ''}")
        failures += 0 if ok else 1
    print(f"\n{len(checks) - failures}/{len(checks)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
