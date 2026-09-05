#!/usr/bin/env python3
"""
CCS-side receipt builder for the BoundaryAttest x CCS paired fixture (01-deny).

Reads the neutral ../../event.json, emits a native CCS L1 receipt using the
same canonicalization (JCS, RFC 8785) and signing (Ed25519) conventions as the
rest of this conformance suite, plus tool-args / response-body / expected
artifacts.  The key is generated deterministically from a fixed fixture seed so
the artifacts are reproducible.  This key is fixture-only and must never be
reused outside this fixture.

Independence rule (agreed in issue #1): the CCS side imports NO BoundaryAttest
code; the BoundaryAttest side imports no CCS code.  Each verifier only ever
sees its own native artifact.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent.parent / "event.json"

FIXTURE_SEED = b"paired-boundaryattest-ccs/01-deny fixture-only key v1"

# L1 receipt field order (same as the v1.4.0 conformance suite).
L1_FIELDS = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary",
    "rule_version", "request_hash", "response_hash", "runtime_context_hash",
    "config_hash", "verifier_source_class", "deployment_mode", "issuer",
    "audience", "nonce", "sequence", "issued_at", "expires_at",
    "max_clock_skew", "action", "signature", "signing_algorithm",
    "public_key_fingerprint", "public_key", "verified_at", "latency_us",
)

RECEIPT_VERSION = "1.4"
TTL = 86400
MAX_CLOCK_SKEW = 30
ISSUER = "ccs-fixture/paired-boundaryattest-01-deny"
AUDIENCE = "independent-verifier"
DEPLOYMENT_MODE = "sidecar"
VERIFIER_SOURCE_CLASS = "PairedFixtureGenerator"


def canonical_json(data) -> bytes:
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(data) -> str:
    return sha256_hex(canonical_json(data))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def main() -> int:
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))

    # --- deterministic fixture key ---
    seed = hashlib.sha256(FIXTURE_SEED).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    fingerprint = hashlib.sha256(pub_raw).hexdigest()[:16]

    # --- map neutral event -> CCS-native structures ---
    req = event["request"]
    tool = req["tool"]
    tool_call_id = req["tool_call_id"]
    args = req["arguments"]
    trace_id = event["event_id"]
    verdict = event["decision"]["verdict"].lower()  # "deny" -> CCS verdict "block"? no: keep native mapping
    # CCS verdict vocabulary: allow / block / escalate.  Neutral DENY maps to
    # CCS native "block" (pre-admission refusal).  The mapping itself is
    # recorded as an interop NOTE, not hidden.
    ccs_verdict = {"DENY": "block", "ALLOW": "allow",
                   "ESCALATE": "escalate"}[event["decision"]["verdict"]]

    decided_epoch = 1788584400  # 2026-09-05T05:00:00Z, deterministic fixture clock

    rule_summary = f"{event['policy']['policy_ref']} v{event['policy']['policy_version']}: {event['decision']['reason']}"
    rule_version = event["policy"]["policy_version"]

    args_digest = canonical_sha256_hex(args)
    param_keys = sorted(args.keys())
    params_envelope = {"tool": tool, "param_keys": param_keys}
    params_hash = canonical_sha256_hex(params_envelope)

    request_envelope = {"tool": tool, "tool_call_id": tool_call_id, "args": args}
    request_hash = canonical_sha256_hex(request_envelope)

    # DENY is pre-admission: no execution happened, so there is no tool
    # response body.  The response envelope records the gate's refusal instead;
    # this semantic choice is documented in NOTES.
    response_body = {
        "executed": False,
        "gate_verdict": "DENY",
        "reason_code": event["decision"]["reason_code"],
        "reason": event["decision"]["reason"],
    }
    response_hash = canonical_sha256_hex(response_body)

    runtime_context = {
        "run_id": event["actor"]["run_id"],
        "agent_id": event["actor"]["agent_id"],
        "agent_version": event["actor"]["agent_version"],
        "model": event["actor"]["model"],
    }
    ctx_envelope = {"trace_id": trace_id, "tool_call_id": tool_call_id,
                    "runtime": runtime_context}
    runtime_context_hash = canonical_sha256_hex(ctx_envelope)

    config_envelope = {
        "rule_version": rule_version, "issuer": ISSUER, "audience": AUDIENCE,
        "deployment_mode": DEPLOYMENT_MODE,
        "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "receipt_ttl_seconds": TTL, "max_clock_skew": MAX_CLOCK_SKEW,
        "public_key_fingerprint": fingerprint,
        # policy binding beyond rule_version (extension inside signed config):
        "policy_ref": event["policy"]["policy_ref"],
        "policy_digest": event["policy"]["policy_digest"],
    }
    config_hash = canonical_sha256_hex(config_envelope)

    receipt = {
        "trace_id": trace_id,
        "receipt_version": RECEIPT_VERSION,
        "verdict": ccs_verdict,
        "timestamp": float(decided_epoch),
        "tool": tool,
        "tool_call_id": tool_call_id,
        "params_hash": params_hash,
        "args_digest": args_digest,
        "rule_summary": rule_summary,
        "rule_version": rule_version,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "runtime_context_hash": runtime_context_hash,
        "config_hash": config_hash,
        "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "deployment_mode": DEPLOYMENT_MODE,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "nonce": f"fixture-nonce-{trace_id}",
        "sequence": 1,
        "issued_at": float(decided_epoch),
        "expires_at": float(decided_epoch + TTL),
        "max_clock_skew": MAX_CLOCK_SKEW,
        "action": f"{tool}.execute",
        "signing_algorithm": "Ed25519",
        "public_key_fingerprint": fingerprint,
        "public_key": pub_b64,
        "verified_at": float(decided_epoch),
        "latency_us": 84.0,
    }
    assert set(receipt.keys()) | {"signature"} == set(L1_FIELDS), set(L1_FIELDS) - set(receipt.keys())

    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    signature = priv.sign(canonical_json(signing_input))
    receipt["signature"] = base64.b64encode(signature).decode("ascii")
    receipt = {k: receipt[k] for k in L1_FIELDS}

    # --- write artifacts ---
    write_json(HERE / "receipt.json", receipt)
    write_bytes(HERE / "signing-input.jcs", canonical_json(signing_input))
    write_bytes(HERE / "signature.sig", signature)
    write_text(HERE / "public-key.b64", pub_b64 + "\n")
    write_json(HERE / "tool-args.json", args)
    write_json(HERE / "response-body.json", response_body)
    write_json(HERE / "expected.json", {
        "event_id": trace_id,
        "ccs_verdict": ccs_verdict,
        "neutral_verdict": event["decision"]["verdict"],
        "signature_valid": True,
        "public_key_fingerprint": fingerprint,
        "args_digest": args_digest,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "config_hash": config_hash,
        "note": "Verify with verify_ccs_receipt.py. Key is fixture-only.",
    })
    print("CCS receipt built:")
    print(f"  receipt.json         verdict={ccs_verdict} fp={fingerprint}")
    print(f"  args_digest          {args_digest}")
    print(f"  request_hash         {request_hash}")
    print(f"  config_hash(policy)  {config_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
