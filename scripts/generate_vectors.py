#!/usr/bin/env python3
"""Generate CCS v1.4.0 conformance vectors (CC0 public domain).

Deterministic key derivation + JCS canonicalization + Ed25519 signing.
All values are fixed for reproducibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import copy
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Deterministic key
# ---------------------------------------------------------------------------
SEED = b"ccs-conformance-vectors/v1/independent-checker"
KEY_SEED = hashlib.sha256(SEED).digest()
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(KEY_SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_RAW = PUBLIC_KEY.public_bytes(Encoding.Raw, PublicFormat.Raw)
PUBLIC_KEY_B64 = base64.b64encode(PUBLIC_KEY_RAW).decode("ascii")
PUBLIC_KEY_FINGERPRINT = hashlib.sha256(PUBLIC_KEY_RAW).hexdigest()[:16]

# ---------------------------------------------------------------------------
# Fixed constants
# ---------------------------------------------------------------------------
TRACE_ID = "conformance-v1.4.0-trace"
ISSUER = "ccs-conformance/v1.4.0"
AUDIENCE = "independent-verifier"
RULE_VERSION = "1.4.0-conformance"
RULE_SUMMARY = "conformance-reference-policy"
RECEIPT_VERSION = "1.4"
VERIFIER_SOURCE_CLASS = "ConformanceVectorGenerator"
DEPLOYMENT_MODE = "in-process"
MAX_CLOCK_SKEW = 30
TTL = 86400  # 24 hours

# Fixed timestamps (epoch seconds) – 2025-06-15T12:00:00Z
BASE_TS = 1750003200.0  # 2025-06-15 12:00:00 UTC
NONCE_COUNTER = 0

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "v1.4.0-conformance"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

L1_FIELDS = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool", "tool_call_id",
    "params_hash", "args_digest", "rule_summary", "rule_version",
    "request_hash", "response_hash", "runtime_context_hash", "config_hash",
    "verifier_source_class", "deployment_mode", "issuer", "audience", "nonce",
    "sequence", "issued_at", "expires_at", "max_clock_skew", "action",
    "signature", "signing_algorithm", "public_key_fingerprint", "public_key",
    "verified_at", "latency_us",
)


def canonical_json(data: Any) -> bytes:
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(data: Any) -> str:
    return sha256_hex(canonical_json(data))


def next_nonce() -> str:
    global NONCE_COUNTER
    n = f"conformance-nonce-{NONCE_COUNTER:04d}"
    NONCE_COUNTER += 1
    return n


def sign_payload(payload: dict[str, Any]) -> str:
    """Sign a dict with the deterministic Ed25519 key (excluding 'signature')."""
    signed = {k: v for k, v in payload.items() if k != "signature"}
    sig = PRIVATE_KEY.sign(canonical_json(signed))
    return base64.b64encode(sig).decode("ascii")


def build_receipt(
    *,
    tool: str,
    tool_call_id: str,
    args: dict[str, Any],
    response_body: Any,
    sequence: int,
    verdict: str = "allow",
    rule_summary: str | None = None,
    runtime_context: dict[str, Any] | None = None,
    started_at: float | None = None,
    latency_us: float = 1234.5,
    issued_at: float | None = None,
    expires_at: float | None = None,
) -> dict[str, Any]:
    """Build a fully signed 30-field L1 receipt."""
    if started_at is None:
        started_at = BASE_TS + sequence * 1.0
    if issued_at is None:
        issued_at = started_at
    if expires_at is None:
        expires_at = issued_at + TTL
    if rule_summary is None:
        rule_summary = RULE_SUMMARY
    if runtime_context is None:
        runtime_context = {"run_id": f"run-{TRACE_ID}", "step": sequence, "model": "conformance-reference"}

    # Hashes
    args_digest = canonical_sha256_hex(args)
    param_keys = sorted(args.keys()) if isinstance(args, dict) else []
    params_hash = canonical_sha256_hex({"tool": tool, "param_keys": param_keys})
    request_envelope = {"tool": tool, "tool_call_id": tool_call_id, "args": args}
    request_hash = canonical_sha256_hex(request_envelope)
    response_hash = canonical_sha256_hex(response_body)

    ctx_envelope = {
        "trace_id": TRACE_ID,
        "tool_call_id": tool_call_id,
        "runtime": runtime_context,
    }
    runtime_context_hash = canonical_sha256_hex(ctx_envelope)

    config_envelope = {
        "rule_version": RULE_VERSION,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "deployment_mode": DEPLOYMENT_MODE,
        "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "receipt_ttl_seconds": TTL,
        "max_clock_skew": MAX_CLOCK_SKEW,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    }
    config_hash = canonical_sha256_hex(config_envelope)

    action = f"{tool}.execute"

    receipt: dict[str, Any] = {
        "trace_id": TRACE_ID,
        "receipt_version": RECEIPT_VERSION,
        "verdict": verdict,
        "timestamp": started_at,
        "tool": tool,
        "tool_call_id": tool_call_id,
        "params_hash": params_hash,
        "args_digest": args_digest,
        "rule_summary": rule_summary,
        "rule_version": RULE_VERSION,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "runtime_context_hash": runtime_context_hash,
        "config_hash": config_hash,
        "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "deployment_mode": DEPLOYMENT_MODE,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "nonce": next_nonce(),
        "sequence": sequence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_clock_skew": MAX_CLOCK_SKEW,
        "action": action,
        "signing_algorithm": "Ed25519",
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "public_key": PUBLIC_KEY_B64,
        "verified_at": started_at,
        "latency_us": latency_us,
    }

    receipt["signature"] = sign_payload(receipt)

    # Ensure exact 30 fields in canonical order
    assert set(receipt.keys()) == set(L1_FIELDS), (
        f"Field mismatch: extra={set(receipt)-set(L1_FIELDS)} missing={set(L1_FIELDS)-set(receipt)}"
    )
    return {k: receipt[k] for k in L1_FIELDS}


def write_json(path: Path, data: Any) -> None:
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


def save_case_files(case_dir: Path, receipt: dict[str, Any]) -> None:
    """Save receipt.json, signing-input.jcs, signature.sig, public-key.b64."""
    case_dir.mkdir(parents=True, exist_ok=True)

    # receipt.json
    write_json(case_dir / "receipt.json", receipt)

    # signing-input.jcs = JCS of receipt minus signature
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))

    # signature.sig = raw 64-byte signature
    sig_raw = base64.b64decode(receipt["signature"])
    write_bytes(case_dir / "signature.sig", sig_raw)

    # public-key.b64
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")


# ---------------------------------------------------------------------------
# Case 01: allow
# ---------------------------------------------------------------------------

def gen_01_allow() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "01-allow"
    args = {"customer_id": "CUST-10042", "include_history": True}
    response_body = {
        "customer_id": "CUST-10042",
        "name": "Alice Zhang",
        "tier": "premium",
        "active": True,
    }
    receipt = build_receipt(
        tool="lookup_customer",
        tool_call_id="call-conformance-01",
        args=args,
        response_body=response_body,
        sequence=0,
        verdict="allow",
        started_at=BASE_TS,
        latency_us=842.0,
    )
    save_case_files(case_dir, receipt)
    write_json(case_dir / "response-body.json", response_body)
    write_json(case_dir / "tool-args.json", args)
    write_json(case_dir / "expected.json", {
        "verdict": "valid",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "hash:response_hash-matches",
            "hash:request_hash-matches",
            "hash:args_digest-matches",
            "hash:params_hash-matches",
            "hash:runtime_context_hash-matches",
            "hash:config_hash-matches",
            "timestamp:valid-instant",
            "cross-field:expires_at>=issued_at",
            "cross-field:fingerprint-matches",
            "cross-field:verdict-response-consistent",
        ],
    })
    write_text(case_dir / "README.md", """# Case 01 — Allow (Positive Vector)

A normal, fully-compliant tool call that CCS allows.

- **Tool**: `lookup_customer`
- **Args**: `{"customer_id": "CUST-10042", "include_history": true}`
- **Response**: Customer record for Alice Zhang (premium tier)
- **Verdict**: `allow`
- **Signature**: Valid Ed25519 over JCS-canonicalized receipt
- **All hashes**: Consistent with their respective payloads

The independent checker must return `valid` with all checks passing.
""")
    return {"case": "01-allow", "verdict": "valid", "receipt": "01-allow/receipt.json"}


# ---------------------------------------------------------------------------
# Case 02: deny-pre-admission (block)
# ---------------------------------------------------------------------------

def gen_02_deny() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "02-deny-pre-admission"
    args = {"account_id": "ACC-99999", "amount": 99999, "currency": "USD"}
    response_body = {
        "blocked": True,
        "reason": "Refund amount 99999 exceeds threshold; pre-admission policy denied.",
    }
    runtime_ctx = {"run_id": f"run-{TRACE_ID}", "step": 1, "model": "conformance-reference"}
    receipt = build_receipt(
        tool="process_refund",
        tool_call_id="call-conformance-02",
        args=args,
        response_body=response_body,
        sequence=1,
        verdict="block",
        rule_summary="Refund amount exceeds per-transaction threshold (max 10000)",
        runtime_context=runtime_ctx,
        started_at=BASE_TS + 1.0,
        latency_us=56.3,
    )
    save_case_files(case_dir, receipt)
    write_json(case_dir / "response-body.json", response_body)
    write_json(case_dir / "tool-args.json", args)
    write_json(case_dir / "expected.json", {
        "verdict": "valid",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "hash:response_hash-matches",
            "hash:request_hash-matches",
            "hash:args_digest-matches",
            "hash:params_hash-matches",
            "hash:runtime_context_hash-matches",
            "hash:config_hash-matches",
            "timestamp:valid-instant",
            "cross-field:expires_at>=issued_at",
            "cross-field:fingerprint-matches",
            "cross-field:verdict-response-consistent",
            "cross-field:block-envelope-present",
        ],
    })
    write_text(case_dir / "README.md", """# Case 02 — Deny Pre-Admission (Positive Block Vector)

A tool call that CCS blocks **before** the tool body executes.

- **Tool**: `process_refund`
- **Args**: `{"account_id": "ACC-99999", "amount": 99999, "currency": "USD"}`
- **Response**: `{"blocked": true, "reason": "Refund amount 99999 exceeds threshold; pre-admission policy denied."}`
- **Verdict**: `block`
- **Rule summary**: Refund amount exceeds per-transaction threshold (max 10000)
- **Signature**: Valid

When verdict is `block`, the response body must be a block envelope containing
`{"blocked": true, "reason": "..."}`. The checker verifies this cross-field
consistency.
""")
    return {"case": "02-deny-pre-admission", "verdict": "valid", "receipt": "02-deny-pre-admission/receipt.json"}


# ---------------------------------------------------------------------------
# Case 03: chain of 3
# ---------------------------------------------------------------------------

def gen_03_chain() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "03-chain-of-3"
    case_dir.mkdir(parents=True, exist_ok=True)

    run_id = f"run-{TRACE_ID}"
    results = []

    chain_calls = [
        {
            "tool": "search_inventory",
            "tool_call_id": "call-conformance-03a",
            "args": {"query": "wireless mouse", "warehouse": "us-west"},
            "response_body": {"items": [{"sku": "WM-001", "qty": 42}, {"sku": "WM-002", "qty": 7}]},
            "sequence": 0,
        },
        {
            "tool": "get_product_details",
            "tool_call_id": "call-conformance-03b",
            "args": {"sku": "WM-001"},
            "response_body": {"sku": "WM-001", "name": "Ergonomic Wireless Mouse", "price": 29.99, "weight_kg": 0.15},
            "sequence": 1,
        },
        {
            "tool": "create_order",
            "tool_call_id": "call-conformance-03c",
            "args": {"sku": "WM-001", "qty": 2, "shipping_address": "123 Main St"},
            "response_body": {"order_id": "ORD-55001", "status": "confirmed", "estimated_delivery": "2025-06-18"},
            "sequence": 2,
        },
    ]

    for i, call in enumerate(chain_calls):
        runtime_ctx = {"run_id": run_id, "step": call["sequence"], "model": "conformance-reference", "session": "chain-session-01"}
        receipt = build_receipt(
            tool=call["tool"],
            tool_call_id=call["tool_call_id"],
            args=call["args"],
            response_body=call["response_body"],
            sequence=call["sequence"],
            verdict="allow",
            runtime_context=runtime_ctx,
            started_at=BASE_TS + i * 2.5,
            latency_us=1000.0 + i * 200,
        )
        fname = f"receipt-{call['sequence']+1}.json"
        write_json(case_dir / fname, receipt)

        # Also save individual signing artifacts
        signing_input = {k: v for k, v in receipt.items() if k != "signature"}
        write_bytes(case_dir / f"signing-input-{call['sequence']+1}.jcs", canonical_json(signing_input))

        write_json(case_dir / f"response-body-{call['sequence']+1}.json", call["response_body"])
        write_json(case_dir / f"tool-args-{call['sequence']+1}.json", call["args"])

        results.append(fname)

    # Public key
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")

    write_json(case_dir / "expected.json", {
        "verdict": "valid",
        "chain_length": 3,
        "shared_trace_id": TRACE_ID,
        "shared_run_id": run_id,
        "sequences": [0, 1, 2],
        "checks": [
            "chain:all-signatures-valid",
            "chain:trace-id-consistent",
            "chain:sequences-monotonic",
            "chain:runtime-context-linked",
            "structure:each-30-fields",
        ],
    })
    write_text(case_dir / "README.md", """# Case 03 — Chain of 3 (Positive Chain Vector)

Three consecutive L1 receipts from the same agent session, forming a chain.

- **Trace ID**: `conformance-v1.4.0-trace` (shared)
- **Run ID**: `run-conformance-v1.4.0-trace` (in runtime_context_hash)
- **Sequences**: 0 → 1 → 2
- **Tools**: `search_inventory` → `get_product_details` → `create_order`
- **All verdicts**: `allow`
- **All signatures**: Valid Ed25519

The checker verifies:
1. Each receipt has a valid signature
2. All receipts share the same `trace_id`
3. Sequence numbers are monotonically increasing
4. The `runtime_context_hash` in each receipt encodes the same `run_id`,
   linking them into one agent session
""")
    return {"case": "03-chain-of-3", "verdict": "valid", "receipts": results}


# ---------------------------------------------------------------------------
# Case 04: tampered negative
# ---------------------------------------------------------------------------

def gen_04_tampered() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "04-tampered-negative"
    case_dir.mkdir(parents=True, exist_ok=True)

    # First build a valid receipt
    args = {"customer_id": "CUST-20001", "region": "eu-north"}
    response_body = {"customer_id": "CUST-20001", "name": "Bob Li", "tier": "standard", "active": False}
    original = build_receipt(
        tool="lookup_customer",
        tool_call_id="call-conformance-04",
        args=args,
        response_body=response_body,
        sequence=0,
        verdict="allow",
        started_at=BASE_TS,
        latency_us=310.0,
    )

    # Save original
    write_json(case_dir / "original-receipt.json", original)
    save_case_files(case_dir / "original", original)
    write_json(case_dir / "original" / "response-body.json", response_body)
    write_json(case_dir / "original" / "tool-args.json", args)

    # Tamper: change verdict from "allow" to "block" without re-signing
    tampered = copy.deepcopy(original)
    tampered["verdict"] = "block"

    write_json(case_dir / "receipt-tampered.json", tampered)

    # Save tampered signing input (different bytes due to verdict change)
    tampered_signing = {k: v for k, v in tampered.items() if k != "signature"}
    write_bytes(case_dir / "signing-input-tampered.jcs", canonical_json(tampered_signing))

    write_text(case_dir / "tamper-description.md", """# Tamper Description

**Original value**: `verdict = "allow"`
**Tampered value**: `verdict = "block"`
**Signature**: NOT re-signed after tampering

The signature was computed over the JCS canonical form of the original receipt
(with `verdict: "allow"`). After changing `verdict` to `"block"`, the canonical
bytes differ, so the Ed25519 signature verification fails.

The independent checker must detect this and return:
```json
{"verdict": "invalid", "reason": "signature mismatch"}
```
""")

    write_json(case_dir / "expected.json", {
        "verdict": "invalid",
        "reason": "signature mismatch",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-INVALID",
        ],
        "tampered_field": "verdict",
        "original_value": "allow",
        "tampered_value": "block",
    })
    write_text(case_dir / "README.md", """# Case 04 — Tampered Negative Vector

A valid receipt is modified after signing without re-signing.

- **Original verdict**: `allow`
- **Tampered verdict**: `block`
- **Signature**: Unchanged from original (now invalid)
- **Expected checker result**: `invalid` — `signature mismatch`

This tests that the checker cryptographically verifies the signature rather
than trusting the receipt's self-declared fields.
""")
    return {"case": "04-tampered-negative", "verdict": "invalid", "receipt": "04-tampered-negative/receipt-tampered.json"}


# ---------------------------------------------------------------------------
# Case 05a: invalid timestamp (month=13)
# ---------------------------------------------------------------------------

def gen_05a_timestamp() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "05-cross-field-semantic" / "05a-invalid-timestamp-month13"
    case_dir.mkdir(parents=True, exist_ok=True)

    args = {"report_id": "RPT-001", "format": "pdf"}
    response_body = {"report_id": "RPT-001", "status": "ready", "download_url": "https://example.com/r/001.pdf"}

    # Build a valid receipt first
    receipt = build_receipt(
        tool="generate_report",
        tool_call_id="call-conformance-05a",
        args=args,
        response_body=response_body,
        sequence=0,
        verdict="allow",
        started_at=BASE_TS,
        latency_us=2500.0,
    )

    # Now tamper with issued_at to be an impossible date string (month=13)
    # The receipt is re-signed (signer vouches for it), but semantic validation
    # must reject the impossible date.
    receipt["issued_at"] = "2025-13-01T00:00:00Z"
    receipt["expires_at"] = "2025-13-02T00:00:00Z"
    receipt["signature"] = sign_payload(receipt)

    write_json(case_dir / "receipt.json", receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))
    sig_raw = base64.b64decode(receipt["signature"])
    write_bytes(case_dir / "signature.sig", sig_raw)
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(case_dir / "response-body.json", response_body)
    write_json(case_dir / "tool-args.json", args)

    write_json(case_dir / "expected.json", {
        "verdict": "invalid",
        "reason": "timestamp denotes impossible instant",
        "field": "issued_at",
        "value": "2025-13-01T00:00:00Z",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "timestamp:IMPOSSIBLE-DATE",
        ],
    })
    return {"case": "05a-invalid-timestamp-month13", "verdict": "invalid", "reason": "timestamp denotes impossible instant"}


# ---------------------------------------------------------------------------
# Case 05b: sandbox flag mismatch
# ---------------------------------------------------------------------------

def gen_05b_sandbox() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "05-cross-field-semantic" / "05b-sandbox-flag-mismatch"
    case_dir.mkdir(parents=True, exist_ok=True)

    # Runtime context declares sandbox=true, but issuer is production
    runtime_ctx = {
        "run_id": f"run-{TRACE_ID}",
        "step": 0,
        "model": "conformance-reference",
        "sandbox": True,
        "environment": "production",
        "principal": "prod-agent-principal",
    }
    args = {"action": "delete_cache", "target": "all"}
    response_body = {"cleared": True, "entries_removed": 1024}

    receipt = build_receipt(
        tool="cache_admin",
        tool_call_id="call-conformance-05b",
        args=args,
        response_body=response_body,
        sequence=0,
        verdict="allow",
        runtime_context=runtime_ctx,
        started_at=BASE_TS,
        latency_us=45.0,
    )

    # The receipt is validly signed. The semantic issue is cross-field:
    # runtime_context.sandbox=true but issuer/principal indicates production.
    # checker must validate this by comparing runtime context against issuer.

    write_json(case_dir / "receipt.json", receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))
    sig_raw = base64.b64decode(receipt["signature"])
    write_bytes(case_dir / "signature.sig", sig_raw)
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(case_dir / "response-body.json", response_body)
    write_json(case_dir / "tool-args.json", args)
    write_json(case_dir / "runtime-context.json", runtime_ctx)

    write_json(case_dir / "expected.json", {
        "verdict": "invalid",
        "reason": "sandbox flag not bound to principal",
        "field": "runtime_context.runtime.sandbox",
        "detail": "sandbox=true but issuer/principal indicates production environment",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "cross-field:sandbox-flag-mismatch",
        ],
    })
    return {"case": "05b-sandbox-flag-mismatch", "verdict": "invalid", "reason": "sandbox flag not bound to principal"}


# ---------------------------------------------------------------------------
# Case 05c: response hash mismatch
# ---------------------------------------------------------------------------

def gen_05c_response_hash() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "05-cross-field-semantic" / "05c-response-hash-mismatch"
    case_dir.mkdir(parents=True, exist_ok=True)

    args = {"user_id": "U-777", "permission": "read"}
    # The actual response
    actual_response = {"user_id": "U-777", "permission": "read", "granted": True, "scope": "basic"}

    # Build receipt with a DIFFERENT response hash (signer signed wrong hash)
    receipt = build_receipt(
        tool="check_permission",
        tool_call_id="call-conformance-05c",
        args=args,
        response_body=actual_response,
        sequence=0,
        verdict="allow",
        started_at=BASE_TS,
        latency_us=88.0,
    )

    # Tamper with response_hash to a wrong value, then re-sign
    # (The signer is either buggy or malicious; signature is valid but semantic fails)
    wrong_hash = "a" * 64  # 64 zeros hex
    receipt["response_hash"] = wrong_hash
    receipt["signature"] = sign_payload(receipt)

    write_json(case_dir / "receipt.json", receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))
    sig_raw = base64.b64decode(receipt["signature"])
    write_bytes(case_dir / "signature.sig", sig_raw)
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(case_dir / "response-body.json", actual_response)
    write_json(case_dir / "tool-args.json", args)

    write_json(case_dir / "expected.json", {
        "verdict": "invalid",
        "reason": "response_hash does not match response body",
        "field": "response_hash",
        "declared_hash": wrong_hash,
        "actual_hash": canonical_sha256_hex(actual_response),
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "hash:response_hash-MISMATCH",
        ],
    })
    return {"case": "05c-response-hash-mismatch", "verdict": "invalid", "reason": "response_hash does not match response body"}


# ---------------------------------------------------------------------------
# Case 05d: verdict=block but response is not block envelope
# ---------------------------------------------------------------------------

def gen_05d_verdict_response_inconsistency() -> dict[str, Any]:
    case_dir = VECTORS_DIR / "05-cross-field-semantic" / "05d-verdict-response-inconsistency"
    case_dir.mkdir(parents=True, exist_ok=True)

    args = {"account_id": "ACC-12345", "amount": 50}
    # A normal (non-block) response body
    normal_response = {"transaction_id": "TXN-88001", "status": "completed", "amount": 50}

    # Build receipt with verdict=block but response_hash pointing to a normal response
    receipt = build_receipt(
        tool="process_refund",
        tool_call_id="call-conformance-05d",
        args=args,
        response_body=normal_response,
        sequence=0,
        verdict="block",
        rule_summary="Test policy: block all refunds",
        started_at=BASE_TS,
        latency_us=120.0,
    )

    # Receipt is validly signed. Semantic issue: deny verdict should not carry
    # a response commitment (normal response body instead of block envelope)
    write_json(case_dir / "receipt.json", receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))
    sig_raw = base64.b64decode(receipt["signature"])
    write_bytes(case_dir / "signature.sig", sig_raw)
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(case_dir / "response-body.json", normal_response)
    write_json(case_dir / "tool-args.json", args)

    write_json(case_dir / "expected.json", {
        "verdict": "invalid",
        "reason": "deny verdict carries response commitment",
        "field": "verdict/response_hash",
        "detail": "verdict=block but response body is not a block envelope {blocked:true,...}",
        "checks": [
            "structure:30-fields",
            "signature:ed25519-valid",
            "cross-field:verdict-response-INCONSISTENT",
        ],
    })
    return {"case": "05d-verdict-response-inconsistency", "verdict": "invalid", "reason": "deny verdict carries response commitment"}


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def gen_manifest() -> None:
    files = {}
    for root, dirs, fnames in os.walk(VECTORS_DIR):
        # Skip hidden / our own dir
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            if fname == "manifest.json":
                continue
            rel = fpath.relative_to(VECTORS_DIR).as_posix()
            files[rel] = sha256_file(fpath)

    manifest = {
        "version": "1.4.0-conformance",
        "generated_by": "generate_vectors.py",
        "seed": SEED.decode(),
        "public_key_b64": PUBLIC_KEY_B64,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "signing_algorithm": "Ed25519",
        "canonicalization": "JCS (RFC 8785)",
        "files": dict(sorted(files.items())),
    }
    write_json(VECTORS_DIR / "manifest.json", manifest)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    results.append(gen_01_allow())
    results.append(gen_02_deny())
    results.append(gen_03_chain())
    results.append(gen_04_tampered())
    results.append(gen_05a_timestamp())
    results.append(gen_05b_sandbox())
    results.append(gen_05c_response_hash())
    results.append(gen_05d_verdict_response_inconsistency())

    # 05 parent README
    write_text(VECTORS_DIR / "05-cross-field-semantic" / "README.md", """# Case 05 — Cross-Field Semantic Negative Vectors

These vectors test semantic validation **beyond** structural and signature checks.
They were specifically requested by Henri Sirkkavaara (Vaara) on the IETF SCITT
mailing list to catch implementation bugs that pure signature verification misses.

| Sub-case | Issue | Signature | Expected |
|---|---|---|---|
| 05a | Timestamp denotes impossible date (month=13) | Valid | invalid |
| 05b | Sandbox flag not bound to principal | Valid | invalid |
| 05c | response_hash doesn't match response body | Valid | invalid |
| 05d | verdict=block but response is not block envelope | Valid | invalid |

Note: In 05c and 05d the signature is cryptographically valid — the signer
signed a receipt that contains semantically incorrect data. This tests that
checkers perform semantic validation independently of signature verification.
""")

    # Manifest must be generated last
    gen_manifest()

    # Summary
    print(f"Generated vectors in {VECTORS_DIR}")
    print(f"Public key:  {PUBLIC_KEY_B64}")
    print(f"Fingerprint: {PUBLIC_KEY_FINGERPRINT}")
    for r in results:
        v = r.get("verdict", "?")
        case = r.get("case", "?")
        reason = r.get("reason", "")
        print(f"  {case}: {v}" + (f" ({reason})" if reason else ""))


if __name__ == "__main__":
    main()
