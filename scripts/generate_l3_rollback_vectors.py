#!/usr/bin/env python3
"""Generate L3-R rollback-evidence extension vectors (CC0 public domain).

Three deterministic cases for the linked rollback-evidence receipt type
(`ccs.rollback-evidence/0.1`), sharing the v1.4.0 corpus key derivation and
JCS/Ed25519 conventions so the existing verifier code path applies unchanged:

  01-rollback-valid      valid executed rollback, bound to a signed target receipt
  02-rollback-unbound    target_receipt_ref points at different bytes -> invalid
  03-rollback-no-tx-ref  executed rollback claim WITHOUT rollback_tx_ref -> invalid (fail-closed)

Each case ships: target-receipt.json (the linked L1-style receipt being rolled
back), receipt.json (the L3-R), signature.sig (detached), signing-input.jcs,
expected.json. Manifest closes the inventory.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

# Same deterministic key derivation as generate_vectors.py
SEED = "ccs-conformance-vectors/v1/independent-checker"
BASE_TS = 1750003200.0  # 2025-06-15 12:00:00 UTC (matches main corpus fixtures)

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "l3-rollback-evidence-v0.1"


def canonical_json(data) -> bytes:
    import jcs
    return jcs.canonicalize(data)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    seed = hashlib.sha256(SEED.encode()).digest()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    return priv, b64(pub)


def sign_claim(priv, payload: dict) -> tuple[dict, bytes]:
    canonical = canonical_json({k: v for k, v in payload.items() if k != "signature"})
    sig = priv.sign(canonical)
    payload["signature"] = b64(sig)
    return payload, canonical


def make_target(priv, pub_b64: str) -> dict:
    """Minimal L1-style target receipt (the payment/execution being rolled back)."""
    payload = {
        "trace_id": "l3r-target-trace-0001",
        "receipt_version": "1.4",
        "verdict": "allow",
        "timestamp": BASE_TS,
        "tool": "payments.refund.execute",
        "_id": "l3r-target-0001",
        "params_hash": "sha256:" + hashlib.sha256(b"params").hexdigest(),
        "args_digest": hashlib.sha256(b"args").hexdigest(),
        "rule_summary": "Payment tool call admitted by policy",
        "rule_version": "conformance-reference-policy",
        "request_hash": "sha256:" + hashlib.sha256(b"request").hexdigest(),
        "response_hash": "sha256:" + hashlib.sha256(b"response").hexdigest(),
        "runtime_context_hash": "sha256:" + hashlib.sha256(b"ctx").hexdigest(),
        "config_hash": "sha256:" + hashlib.sha256(b"config").hexdigest(),
        "verifier_source_class": "ConformanceVectorGenerator",
        "deployment_mode": "in-process",
        "issuer": "conformance-reference-issuer",
        "audience": "conformance-reference-audience",
        "nonce": "l3r-target-nonce-0001",
        "policy": {"policy_id": "conformance-reference-policy"},
        "correlation_id": "5e21b3c4-9f6d-4a7e-8b2a-1c3d5e7f9a01",
        "public_key": pub_b64,
        "public_key_fingerprint": hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:16],
        "signing_algorithm": "Ed25519",
        "issued_at": "2025-06-15T12:00:00Z",
        "verified_at": "2025-06-15T12:00:00Z",
        "expires_at": "2025-06-16T12:00:00Z",
        "max_clock_skew": 30,
        "latency_us": 420,
        "sequence": 1,
    }
    signed, _ = sign_claim(priv, payload)
    signed["settlement"] = {"status": "settled", "settled_at": BASE_TS + 60,
                            "amount_minor": 12500, "currency": "USD"}
    # re-sign including the settlement block (full payload minus signature)
    signed.pop("signature")
    signed, _ = sign_claim(priv, signed)
    return signed


def make_l3r(priv, pub_b64: str, target: dict, *, tamper_binding: bool = False,
             drop_tx_ref: bool = False) -> dict:
    target_digest = "sha256:" + hashlib.sha256(
        canonical_json({k: v for k, v in target.items() if k != "signature"})
    ).hexdigest()
    if tamper_binding:
        # claim to roll back a DIFFERENT (nonexistent) target
        target_digest = "sha256:" + "0" * 64
    payload = {
        "receipt_type": "ccs.rollback-evidence/0.1",
        "receipt_version": "0.1",
        "evidence_type": "rollback-evidence",
        "target_receipt_ref": target_digest,
        "target_receipt_chain_pos": 1,
        "rollback_decision": "settled-payment-reversed",
        "settled_at_original": BASE_TS + 60,
        "rollback_tx_ref": None if drop_tx_ref else "reversal:ch_3Pilot0001_l3r",
        "operator_id": "operator:conformance-rig",
        "decision_basis": "policy:refund-window-24h",
        "timestamp": BASE_TS + 120,
        "nonce": "l3r-nonce-0001",
        "issuer": "conformance-reference-issuer",
        "audience": "conformance-reference-audience",
        "public_key": pub_b64,
    }
    signed, _ = sign_claim(priv, payload)
    return signed


def write_case(case_dir: Path, target: dict, l3r: dict, priv, expected: dict):
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "target-receipt.json").write_text(json.dumps(target, indent=2) + "\n")
    (case_dir / "receipt.json").write_text(json.dumps(l3r, indent=2) + "\n")
    preimage = canonical_json({k: v for k, v in l3r.items() if k != "signature"})
    (case_dir / "signing-input.jcs").write_bytes(preimage)
    sig = base64.b64decode(l3r["signature"])
    (case_dir / "signature.sig").write_bytes(sig)
    (case_dir / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")


def main() -> None:
    priv, pub_b64 = keypair()
    target = make_target(priv, pub_b64)

    cases = {}

    # 01 — valid executed rollback, correctly bound
    c01 = VECTORS_DIR / "01-rollback-valid"
    write_case(c01, target, make_l3r(priv, pub_b64, target), priv,
               {"verdict": "valid",
                "checks": ["structure:l3r-fields", "signature:ed25519-valid",
                           "binding:target-receipt-ref-matches",
                           "failclosed:rollback-tx-ref-present"]})
    cases["01-rollback-valid"] = c01

    # 02 — unbound target (binding recomputation must fail)
    c02 = VECTORS_DIR / "02-rollback-unbound"
    write_case(c02, target, make_l3r(priv, pub_b64, target, tamper_binding=True), priv,
               {"verdict": "invalid", "reason": "target receipt binding failed"})
    cases["02-rollback-unbound"] = c02

    # 03 — executed claim without transaction reference (fail-closed)
    c03 = VECTORS_DIR / "03-rollback-no-tx-ref"
    write_case(c03, target, make_l3r(priv, pub_b64, target, drop_tx_ref=True), priv,
               {"verdict": "invalid",
                "reason": "unverifiable rollback claim: executed decision without rollback_tx_ref"})
    cases["03-rollback-no-tx-ref"] = c03

    # Manifest (closed inventory, same schema as the main corpus)
    files = {}
    for name, cdir in sorted(cases.items()):
        for p in sorted(cdir.iterdir()):
            files[f"{name}/{p.name}"] = hashlib.sha256(p.read_bytes()).hexdigest()
    files["README.md"] = None  # placeholder, filled after write
    files.pop("README.md")
    manifest = {
        "version": "l3-rollback-evidence-v0.1",
        "generated_by": "generate_l3_rollback_vectors.py — 2026-11-07, Correctover",
        "description": "Linked rollback-evidence receipt extension (L3-R): binding + fail-closed tx-ref semantics; deterministic key derivation shared with v1.4.0 corpus",
        "public_key_b64": pub_b64,
        "signing_algorithm": "Ed25519",
        "canonicalization": "JCS (RFC 8785)",
        "files": files,
    }
    (VECTORS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    readme = """# l3-rollback-evidence-v0.1 — linked rollback-evidence receipt extension

First slice of the L3-R extension type (`ccs.rollback-evidence/0.1`): a linked
evidence receipt that attests the rollback of a settled execution, bound to the
target receipt by recomputed digest (not by claim), and fail-closed on
"executed rollback without a transaction reference".

Three deterministic cases (same key derivation and JCS/Ed25519 conventions as
the v1.4.0 corpus; separate nonce space):

- `01-rollback-valid` — valid: signature ok, target binding recomputes, tx ref present.
- `02-rollback-unbound` — MUST-FAIL: target_receipt_ref names different bytes.
- `03-rollback-no-tx-ref` — MUST-FAIL (fail-closed): executed rollback claim with no rollback_tx_ref.

Verify: `python checkers/independent_checker.py vectors/l3-rollback-evidence-v0.1/`

Design notes: `fusion/ccs-扩展设计-回滚证据与归因标签-20261107` (internal).
CC0 for vectors. Test-only key — not a production trust anchor.
"""
    (VECTORS_DIR / "README.md").write_text(readme)
    manifest["files"]["README.md"] = hashlib.sha256((VECTORS_DIR / "README.md").read_bytes()).hexdigest()
    (VECTORS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("wrote", VECTORS_DIR)
    for name in sorted(cases):
        print("  -", name)


if __name__ == "__main__":
    main()
