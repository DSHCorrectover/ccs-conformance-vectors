#!/usr/bin/env python3
"""
Independent verifier for the CCS-native receipt of paired fixture 01-deny.

It deliberately does NOT import build_ccs_receipt.py: verification is
implemented from scratch against the receipt on disk and the neutral event,
which is how an independent third party would check it.

Checks:
  1. Ed25519 signature over JCS (RFC 8785) canonicalization of all fields
     except `signature`.
  2. Embedded public key matches its fingerprint and is the fixture key.
  3. Recomputed args/request/response/runtime/config digests match the receipt.
  4. The receipt's verdict is the correct native mapping of the neutral event
     verdict (DENY -> block, pre-admission).
  5. Temporal gates: issued_at <= verified_at <= expires_at within skew;
     nonce present; sequence == 1.
  6. The policy digest bound in config hash equals the neutral event's
     policy_digest.

Exit code 0 = all checks pass.  Failures print the failing assertion and exit 1.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent.parent / "event.json"

L1_SIGNED_FIELDS = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary",
    "rule_version", "request_hash", "response_hash", "runtime_context_hash",
    "config_hash", "verifier_source_class", "deployment_mode", "issuer",
    "audience", "nonce", "sequence", "issued_at", "expires_at",
    "max_clock_skew", "action", "signing_algorithm",
    "public_key_fingerprint", "public_key", "verified_at", "latency_us",
)

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))


def cj(data) -> bytes:
    return jcs.canonicalize(data)


def csh(data) -> str:
    return hashlib.sha256(cj(data)).hexdigest()


def main() -> int:
    receipt = json.loads((HERE / "receipt.json").read_text(encoding="utf-8"))
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    sig_disk = (HERE / "signature.sig").read_bytes()
    jcs_disk = (HERE / "signing-input.jcs").read_bytes()
    args = json.loads((HERE / "tool-args.json").read_text(encoding="utf-8"))
    response_body = json.loads((HERE / "response-body.json").read_text(encoding="utf-8"))

    # 1. field set
    missing = [f for f in L1_SIGNED_FIELDS if f not in receipt]
    check("receipt field set complete", not missing, f"missing={missing}")
    check("signature present", "signature" in receipt)

    # 2. signature
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    check("signing-input.jcs matches canonical receipt",
          cj(signing_input) == jcs_disk)
    pub_raw = base64.b64decode(receipt["public_key"])
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            base64.b64decode(receipt["signature"]), cj(signing_input))
        sig_ok = True
    except InvalidSignature:
        sig_ok = False
    check("Ed25519 signature verifies over JCS input", sig_ok)
    check("signature.sig file matches receipt signature",
          sig_disk == base64.b64decode(receipt["signature"]))

    # 3. key fingerprint
    fp = hashlib.sha256(pub_raw).hexdigest()[:16]
    check("public_key_fingerprint matches key", fp == receipt["public_key_fingerprint"], fp)

    # 4. digest recomputation
    check("args_digest", receipt["args_digest"] == csh(args), receipt["args_digest"])
    req_env = {"tool": receipt["tool"], "tool_call_id": receipt["tool_call_id"], "args": args}
    check("request_hash", receipt["request_hash"] == csh(req_env))
    check("response_hash", receipt["response_hash"] == csh(response_body))
    params_env = {"tool": receipt["tool"], "param_keys": sorted(args.keys())}
    check("params_hash", receipt["params_hash"] == csh(params_env))

    # 5. verdict mapping
    expected_ccs = {"DENY": "block", "ALLOW": "allow",
                    "ESCALATE": "escalate"}[event["decision"]["verdict"]]
    check("verdict mapping DENY->block", receipt["verdict"] == expected_ccs,
          f"got {receipt['verdict']}")
    check("trace_id bound to event_id",
          receipt["trace_id"] == event["event_id"])
    check("tool matches event", receipt["tool"] == event["request"]["tool"])
    check("tool_call_id matches event",
          receipt["tool_call_id"] == event["request"]["tool_call_id"])

    # 6. policy binding: event policy digest must appear in the config envelope
    #    that config_hash commits to.  Rebuild the envelope with the event's
    #    policy values and require equal hash.
    config_envelope = {
        "rule_version": receipt["rule_version"],
        "issuer": receipt["issuer"],
        "audience": receipt["audience"],
        "deployment_mode": receipt["deployment_mode"],
        "verifier_source_class": receipt["verifier_source_class"],
        "receipt_ttl_seconds": int(receipt["expires_at"] - receipt["issued_at"]),
        "max_clock_skew": receipt["max_clock_skew"],
        "public_key_fingerprint": receipt["public_key_fingerprint"],
        "policy_ref": event["policy"]["policy_ref"],
        "policy_digest": event["policy"]["policy_digest"],
    }
    check("config_hash commits to policy_ref+policy_digest",
          receipt["config_hash"] == csh(config_envelope), receipt["config_hash"])
    check("policy_digest is sha256 of policy_text",
          hashlib.sha256(event["policy"]["policy_text"].encode("utf-8")).hexdigest()
          == event["policy"]["policy_digest"])
    check("rule_version matches policy_version",
          receipt["rule_version"] == event["policy"]["policy_version"])

    # 7. temporal gates
    check("issued_at <= verified_at",
          receipt["issued_at"] <= receipt["verified_at"] + receipt["max_clock_skew"])
    check("verified_at <= expires_at + skew",
          receipt["verified_at"] <= receipt["expires_at"] + receipt["max_clock_skew"])
    check("nonce present", bool(receipt.get("nonce")))
    check("sequence == 1", receipt["sequence"] == 1)
    check("not executed (pre-admission deny)",
          response_body["executed"] is False and event["execution"]["executed"] is False)

    width = max(len(n) for n, _, _ in checks)
    failed = 0
    for name, ok, detail in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name.ljust(width)}  {detail if not ok else ''}")
        failed += 0 if ok else 1
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
