#!/usr/bin/env python3
"""Generate extended CCS v1.4.0 conformance vectors (CC0 public domain).

Adds L2 behavior receipts, structure negatives, temporal negatives,
identity negatives, chain negatives, integrity negatives, and nonce
negatives on top of the original 8 cases.

Deterministic: same Ed25519 seed, fixed timestamps, no randomness.
Run AFTER generate_vectors.py (which creates the first 8 cases).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Deterministic key (same as generate_vectors.py)
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
TTL = 86400

# 2025-06-15T12:00:00Z
BASE_TS = 1750003200.0
BASE_ISO = "2025-06-15T12:00:00Z"

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "v1.4.0-conformance"

_nonce_counter = 100  # Start after original 8 cases (which used 0..9)


def next_nonce() -> str:
    global _nonce_counter
    n = f"conformance-nonce-{_nonce_counter:04d}"
    _nonce_counter += 1
    return n


L1_FIELDS = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary",
    "rule_version", "request_hash", "response_hash", "runtime_context_hash",
    "config_hash", "verifier_source_class", "deployment_mode", "issuer",
    "audience", "nonce", "sequence", "issued_at", "expires_at",
    "max_clock_skew", "action", "signature", "signing_algorithm",
    "public_key_fingerprint", "public_key", "verified_at", "latency_us",
)

L2_FIELDS = (
    "receipt_type", "trace_id", "tool_call_id", "sequence",
    "linked_l1_receipt_digest", "behavior_evidence_verdict", "evidence_ref",
    "issuer", "audience", "issued_at", "deployment_mode",
    "signing_algorithm", "public_key_fingerprint", "public_key", "signature",
)


def canonical_json(data: Any) -> bytes:
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(data: Any) -> str:
    return sha256_hex(canonical_json(data))


def sign_payload(payload: dict[str, Any]) -> str:
    signed = {k: v for k, v in payload.items() if k != "signature"}
    sig = PRIVATE_KEY.sign(canonical_json(signed))
    return base64.b64encode(sig).decode("ascii")


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

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


def save_l1_artifacts(case_dir: Path, receipt: dict, *, name: str = "receipt") -> None:
    """Save receipt.json, signing-input.jcs, signature.sig, public-key.b64."""
    receipt_path = case_dir / f"{name}.json"
    write_json(receipt_path, receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / f"signing-input{'-' + name.split('-',1)[1] if name != 'receipt' else ''}.jcs",
                canonical_json(signing_input))
    write_bytes(case_dir / f"signature{'-' + name.split('-',1)[1] if name != 'receipt' else ''}.sig",
                base64.b64decode(receipt["signature"]))
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")


def save_single_l1(case_dir: Path, receipt: dict) -> None:
    """Save artifacts for a single receipt case (standard naming)."""
    write_json(case_dir / "receipt.json", receipt)
    signing_input = {k: v for k, v in receipt.items() if k != "signature"}
    write_bytes(case_dir / "signing-input.jcs", canonical_json(signing_input))
    write_bytes(case_dir / "signature.sig", base64.b64decode(receipt["signature"]))
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")


# ---------------------------------------------------------------------------
# L1 receipt builder (configurable)
# ---------------------------------------------------------------------------

def build_l1(
    *,
    tool: str = "lookup_customer",
    tool_call_id: str = "call-ext-001",
    args: dict | None = None,
    response_body: Any = None,
    sequence: int = 0,
    verdict: str = "allow",
    rule_summary: str | None = None,
    runtime_context: dict | None = None,
    timestamp: float | str = BASE_TS,
    issued_at: float | str | None = None,
    expires_at: float | str | None = None,
    verified_at: float | str | None = None,
    max_clock_skew: int | float = MAX_CLOCK_SKEW,
    latency_us: float = 1000.0,
    nonce: str | None = None,
    trace_id: str = TRACE_ID,
    action: str | None = None,
) -> dict:
    if args is None:
        args = {"id": "X-1"}
    if response_body is None:
        response_body = {"ok": True}
    if rule_summary is None:
        rule_summary = RULE_SUMMARY
    if runtime_context is None:
        runtime_context = {"run_id": f"run-{TRACE_ID}", "step": sequence}
    if issued_at is None:
        issued_at = timestamp if isinstance(timestamp, (int, float)) else BASE_ISO
    if expires_at is None:
        if isinstance(issued_at, (int, float)):
            expires_at = issued_at + TTL
        else:
            expires_at = "2025-06-16T12:00:00Z"
    if verified_at is None:
        verified_at = timestamp if isinstance(timestamp, (int, float)) else BASE_ISO
    if nonce is None:
        nonce = next_nonce()
    if action is None:
        action = f"{tool}.execute"

    args_digest = canonical_sha256_hex(args)
    param_keys = sorted(args.keys()) if isinstance(args, dict) else []
    params_envelope = {"tool": tool, "param_keys": param_keys}
    params_hash = canonical_sha256_hex(params_envelope)
    request_envelope = {"tool": tool, "tool_call_id": tool_call_id, "args": args}
    request_hash = canonical_sha256_hex(request_envelope)
    response_hash = canonical_sha256_hex(response_body)

    ctx_envelope = {"trace_id": trace_id, "tool_call_id": tool_call_id, "runtime": runtime_context}
    runtime_context_hash = canonical_sha256_hex(ctx_envelope)

    config_envelope = {
        "rule_version": RULE_VERSION, "issuer": ISSUER, "audience": AUDIENCE,
        "deployment_mode": DEPLOYMENT_MODE, "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "receipt_ttl_seconds": TTL, "max_clock_skew": MAX_CLOCK_SKEW,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    }
    config_hash = canonical_sha256_hex(config_envelope)

    receipt = {
        "trace_id": trace_id,
        "receipt_version": RECEIPT_VERSION,
        "verdict": verdict,
        "timestamp": timestamp,
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
        "nonce": nonce,
        "sequence": sequence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_clock_skew": max_clock_skew,
        "action": action,
        "signing_algorithm": "Ed25519",
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "public_key": PUBLIC_KEY_B64,
        "verified_at": verified_at,
        "latency_us": latency_us,
    }
    receipt["signature"] = sign_payload(receipt)
    assert set(receipt.keys()) == set(L1_FIELDS)
    return {k: receipt[k] for k in L1_FIELDS}


# ---------------------------------------------------------------------------
# L2 builder
# ---------------------------------------------------------------------------

def l1_digest(l1: dict) -> str:
    signed = {k: v for k, v in l1.items() if k != "signature"}
    return "sha256:" + sha256_hex(canonical_json(signed))


def build_l2(
    *,
    l1_receipt: dict,
    behavior_verdict: str = "not_observed",
    evidence_ref: str = "ccs:behavior/none",
    sequence: int = 0,
    tool_call_id: str | None = None,
    trace_id: str | None = None,
    issued_at: str = BASE_ISO,
    linked_digest: str | None = None,
) -> dict:
    if tool_call_id is None:
        tool_call_id = l1_receipt["tool_call_id"]
    if trace_id is None:
        trace_id = l1_receipt["trace_id"]
    if linked_digest is None:
        linked_digest = l1_digest(l1_receipt)

    receipt = {
        "receipt_type": "ccs.behavior_evidence.v1",
        "trace_id": trace_id,
        "tool_call_id": tool_call_id,
        "sequence": sequence,
        "linked_l1_receipt_digest": linked_digest,
        "behavior_evidence_verdict": behavior_verdict,
        "evidence_ref": evidence_ref,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "issued_at": issued_at,
        "deployment_mode": DEPLOYMENT_MODE,
        "signing_algorithm": "Ed25519",
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "public_key": PUBLIC_KEY_B64,
    }
    receipt["signature"] = sign_payload(receipt)
    assert set(receipt.keys()) == set(L2_FIELDS)
    return {k: receipt[k] for k in L2_FIELDS}


# ---------------------------------------------------------------------------
# Generic case writer
# ---------------------------------------------------------------------------

def write_l1_case(
    case_dir: Path,
    receipt: dict,
    *,
    expected: dict,
    readme: str,
    args: dict | None = None,
    response_body: Any = None,
    runtime_context: dict | None = None,
    request_envelope: dict | None = None,
    params_envelope: dict | None = None,
    config_envelope: dict | None = None,
) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    save_single_l1(case_dir, receipt)
    write_json(case_dir / "expected.json", expected)
    write_text(case_dir / "README.md", readme)
    if args is not None:
        write_json(case_dir / "tool-args.json", args)
    if response_body is not None:
        write_json(case_dir / "response-body.json", response_body)
    if runtime_context is not None:
        write_json(case_dir / "runtime-context.json", runtime_context)
    if request_envelope is not None:
        write_json(case_dir / "request-envelope.json", request_envelope)
    if params_envelope is not None:
        write_json(case_dir / "params-envelope.json", params_envelope)
    if config_envelope is not None:
        write_json(case_dir / "config-envelope.json", config_envelope)


# ---------------------------------------------------------------------------
# 06: L2 Behavior Receipts (4 cases)
# ---------------------------------------------------------------------------

def gen_06_l2() -> None:
    group = VECTORS_DIR / "06-l2-behavior"

    # Base L1 receipt that the L2 receipts link to
    l1 = build_l1(
        tool="search_inventory",
        tool_call_id="call-l2-base",
        args={"q": "keyboard"},
        response_body={"items": [{"sku": "KB-1", "qty": 9}]},
        sequence=0,
    )

    # --- 06a: not_observed (valid) ---
    d = group / "06a-behavior-not-observed"
    l2 = build_l2(l1_receipt=l1, behavior_verdict="not_observed",
                  evidence_ref="ccs:behavior/no-observation", sequence=0)
    write_json(d / "receipt.json", l2)
    si = {k: v for k, v in l2.items() if k != "signature"}
    write_bytes(d / "signing-input.jcs", canonical_json(si))
    write_bytes(d / "signature.sig", base64.b64decode(l2["signature"]))
    write_text(d / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(d / "linked-l1-receipt.json", l1)
    write_json(d / "expected.json", {"verdict": "valid", "checks": [
        "structure:15-fields", "signature:ed25519", "l2:linked-l1-digest-matches"]})
    write_text(d / "README.md", """# Case 06a — L2 Behavior: not_observed (Positive)

A behavior evidence receipt asserting that no relevant behavior was observed
for the linked L1 decision. The linked L1 receipt digest is correct and the
signature verifies.
""")

    # --- 06b: observed_and_allowed (valid) ---
    d = group / "06b-behavior-observed-allowed"
    l2 = build_l2(l1_receipt=l1, behavior_verdict="observed_and_allowed",
                  evidence_ref="ccs:behavior/execution-trace-001", sequence=0)
    write_json(d / "receipt.json", l2)
    si = {k: v for k, v in l2.items() if k != "signature"}
    write_bytes(d / "signing-input.jcs", canonical_json(si))
    write_bytes(d / "signature.sig", base64.b64decode(l2["signature"]))
    write_text(d / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(d / "linked-l1-receipt.json", l1)
    write_json(d / "expected.json", {"verdict": "valid"})
    write_text(d / "README.md", """# Case 06b — L2 Behavior: observed_and_allowed (Positive)

Behavior was observed post-decision and found consistent with the allowed
verdict. Linked L1 digest matches.
""")

    # --- 06c: observed_and_rejected (valid) ---
    d = group / "06c-behavior-observed-rejected"
    l2 = build_l2(l1_receipt=l1, behavior_verdict="observed_and_rejected",
                  evidence_ref="ccs:behavior/policy-violation-001", sequence=0)
    write_json(d / "receipt.json", l2)
    si = {k: v for k, v in l2.items() if k != "signature"}
    write_bytes(d / "signing-input.jcs", canonical_json(si))
    write_bytes(d / "signature.sig", base64.b64decode(l2["signature"]))
    write_text(d / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(d / "linked-l1-receipt.json", l1)
    write_json(d / "expected.json", {"verdict": "valid"})
    write_text(d / "README.md", """# Case 06c — L2 Behavior: observed_and_rejected (Positive)

Behavior was observed and rejected (e.g. a later action violated policy).
The receipt itself is structurally and cryptographically valid.
""")

    # --- 06d: wrong L1 digest (invalid) ---
    d = group / "06d-behavior-wrong-l1-digest"
    wrong_digest = "sha256:" + "f" * 64
    l2 = build_l2(l1_receipt=l1, behavior_verdict="not_observed",
                  evidence_ref="ccs:behavior/none", sequence=0,
                  linked_digest=wrong_digest)
    write_json(d / "receipt.json", l2)
    si = {k: v for k, v in l2.items() if k != "signature"}
    write_bytes(d / "signing-input.jcs", canonical_json(si))
    write_bytes(d / "signature.sig", base64.b64decode(l2["signature"]))
    write_text(d / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(d / "linked-l1-receipt.json", l1)
    write_json(d / "expected.json", {
        "verdict": "invalid",
        "reason": "linked_l1_receipt_digest mismatch",
    })
    write_text(d / "README.md", """# Case 06d — L2 Behavior: wrong L1 digest (Negative)

The `linked_l1_receipt_digest` does not match the SHA-256 of the actual
linked L1 receipt. The signature is valid; the failure is semantic.
""")

    write_text(group / "README.md", """# Case 06 — L2 Behavior Evidence Receipts

L2 receipts carry post-decision behavior observations linked to an L1
receipt by content digest. They use 15 fields and are Ed25519-signed over
JCS. See sub-cases for positive and negative vectors.
""")


# ---------------------------------------------------------------------------
# 07: Structure / schema negatives
# ---------------------------------------------------------------------------

def gen_07_structure() -> None:
    group = VECTORS_DIR / "07-structure-negatives"
    args = {"user_id": "U-100", "scope": "read"}
    resp = {"user_id": "U-100", "granted": True}

    # --- 07a-XX: missing each of the 30 fields ---
    for field in L1_FIELDS:
        base = build_l1(
            tool="check_permission",
            tool_call_id=f"call-miss-{field[:8]}",
            args=args, response_body=resp, sequence=0,
        )
        reduced = {k: v for k, v in base.items() if k != field}
        # Re-sign if signature is not the removed field (otherwise leave invalid)
        if field != "signature":
            reduced["signature"] = sign_payload(reduced)
        d = group / f"07a-missing-{field}"
        d.mkdir(parents=True, exist_ok=True)
        write_json(d / "receipt.json", reduced)
        # signing input (what would be signed)
        si = {k: v for k, v in reduced.items() if k != "signature"}
        write_bytes(d / "signing-input.jcs", canonical_json(si))
        if "signature" in reduced:
            write_bytes(d / "signature.sig", base64.b64decode(reduced["signature"]))
        else:
            write_bytes(d / "signature.sig", b"")
        write_text(d / "public-key.b64", PUBLIC_KEY_B64 + "\n")
        write_json(d / "expected.json", {
            "verdict": "invalid",
            "reason": f"missing required field",
            "field": field,
        })
        write_text(d / "README.md", f"""# Case 07a — Missing field: `{field}`

The field `{field}` is removed from an otherwise-valid L1 receipt.
Strict mode requires exactly the 30 defined fields; the checker must reject.
""")

    # --- 07b: unknown field ---
    base = build_l1(
        tool="check_permission", tool_call_id="call-unknown-field",
        args=args, response_body=resp, sequence=0,
    )
    extra = copy.deepcopy(base)
    extra["extension_field"] = "unexpected"
    extra["signature"] = sign_payload(extra)
    d = group / "07b-unknown-field"
    save_single_l1(d, extra)
    write_json(d / "expected.json", {
        "verdict": "invalid",
        "reason": "unknown field in strict mode",
    })
    write_text(d / "README.md", """# Case 07b — Unknown field (Negative)

An extra field `extension_field` is present. strict=True requires rejection
of any field not in the 30-field L1 schema.
""")

    # --- 07c: wrong types (5) ---
    wrong_type_cases = [
        ("verdict-as-number", "verdict", 1, "verdict must be 'allow' or 'block'"),
        ("sequence-as-string", "sequence", "zero", "sequence must be non-negative integer"),
        ("max-clock-skew-as-string", "max_clock_skew", "thirty", "max_clock_skew must be non-negative number"),
        ("latency-as-string", "latency_us", "1000", "latency_us must be non-negative number"),
        ("timestamp-as-boolean", "timestamp", True, "timestamp must not be boolean"),
    ]
    for slug, field, bad_value, reason in wrong_type_cases:
        base = build_l1(
            tool="check_permission", tool_call_id=f"call-type-{slug}",
            args=args, response_body=resp, sequence=0,
        )
        bad = copy.deepcopy(base)
        bad[field] = bad_value
        bad["signature"] = sign_payload(bad)
        d = group / f"07c-{slug}"
        save_single_l1(d, bad)
        write_json(d / "expected.json", {"verdict": "invalid", "reason": reason, "field": field})
        write_text(d / "README.md", f"""# Case 07c — Wrong type: `{field}` (Negative)

Field `{field}` is given a value of incorrect type ({bad_value!r}).
The checker must reject at structural validation.
""")

    write_text(group / "README.md", """# Case 07 — Structure / Schema Negatives

Tests strict schema enforcement:
- 07a: each of the 30 L1 fields removed in turn (30 cases)
- 07b: an unknown extra field
- 07c: five representative type errors
""")


# ---------------------------------------------------------------------------
# 08: Temporal negatives
# ---------------------------------------------------------------------------

def gen_08_temporal() -> None:
    group = VECTORS_DIR / "08-temporal-negatives"
    args = {"report_id": "RPT-T-1"}
    resp = {"report_id": "RPT-T-1", "status": "ready"}

    # 08a: expired — expires_at before issued_at (ISO strings)
    r = build_l1(
        tool="generate_report", tool_call_id="call-expired",
        args=args, response_body=resp, sequence=0,
        timestamp=BASE_ISO,
        issued_at="2025-06-15T12:00:00Z",
        expires_at="2025-06-14T12:00:00Z",  # before issued
        verified_at=BASE_ISO,
    )
    write_l1_case(group / "08a-expired", r, expected={
        "verdict": "invalid", "reason": "expires_at is before issued_at",
    }, readme="# Case 08a — Expired (Negative)\n\n`expires_at` precedes `issued_at`.\n",
       args=args, response_body=resp)

    # 08b: future timestamp — timestamp far beyond clock skew
    r = build_l1(
        tool="generate_report", tool_call_id="call-future",
        args=args, response_body=resp, sequence=0,
        timestamp=BASE_TS + 3600,  # 1 hour in future
        issued_at=BASE_TS,
        expires_at=BASE_TS + TTL,
        verified_at=BASE_TS,
        max_clock_skew=30,
    )
    write_l1_case(group / "08b-future-timestamp", r, expected={
        "verdict": "invalid", "reason": "timestamp skew exceeds max_clock_skew",
    }, readme="# Case 08b — Future timestamp (Negative)\n\n`timestamp` is 1 hour ahead of `verified_at`, exceeding `max_clock_skew=30`.\n",
       args=args, response_body=resp)

    # 08c: issued_at after timestamp
    r = build_l1(
        tool="generate_report", tool_call_id="call-issued-after",
        args=args, response_body=resp, sequence=0,
        timestamp=BASE_ISO,
        issued_at="2025-06-15T13:00:00Z",  # 1 hour after timestamp
        expires_at="2025-06-16T13:00:00Z",
        verified_at=BASE_ISO,
    )
    write_l1_case(group / "08c-issued-after-timestamp", r, expected={
        "verdict": "invalid", "reason": "issued_at is after timestamp",
    }, readme="# Case 08c — issued_at after timestamp (Negative)\n\nThe issuance time is later than the event timestamp.\n",
       args=args, response_body=resp)

    # 08d: clock skew boundary — exactly 1 microsecond over limit
    r = build_l1(
        tool="generate_report", tool_call_id="call-skew-boundary",
        args=args, response_body=resp, sequence=0,
        timestamp=BASE_TS + 30 + 0.000001,
        issued_at=BASE_TS,
        expires_at=BASE_TS + TTL,
        verified_at=BASE_TS,
        max_clock_skew=30,
    )
    write_l1_case(group / "08d-clock-skew-boundary", r, expected={
        "verdict": "invalid", "reason": "timestamp skew exceeds max_clock_skew",
    }, readme="# Case 08d — Clock skew boundary (Negative)\n\nSkew is 30.000001s, just over `max_clock_skew=30`.\n",
       args=args, response_body=resp)

    write_text(group / "README.md", """# Case 08 — Temporal Negatives

Tests time semantics: expiry, clock-skew tolerance, issuance ordering.
""")


# ---------------------------------------------------------------------------
# 09: Identity negatives
# ---------------------------------------------------------------------------

def gen_09_identity() -> None:
    group = VECTORS_DIR / "09-identity-negatives"
    args = {"item": "widget"}
    resp = {"ok": True}

    # 09a: fingerprint mismatch — declare a wrong fingerprint, re-sign
    r = build_l1(tool="echo", tool_call_id="call-fp-mismatch",
                 args=args, response_body=resp, sequence=0)
    r["public_key_fingerprint"] = "0" * 16
    r["signature"] = sign_payload(r)
    write_l1_case(group / "09a-fingerprint-mismatch", r, expected={
        "verdict": "invalid", "reason": "fingerprint mismatch",
    }, readme="# Case 09a — Fingerprint mismatch (Negative)\n\n`public_key_fingerprint` does not equal SHA-256(public_key)[:16].\n",
       args=args, response_body=resp)

    # 09b: wrong algorithm
    r = build_l1(tool="echo", tool_call_id="call-wrong-alg",
                 args=args, response_body=resp, sequence=0)
    r["signing_algorithm"] = "ES256"
    r["signature"] = sign_payload(r)
    write_l1_case(group / "09b-wrong-algorithm", r, expected={
        "verdict": "invalid", "reason": "signing_algorithm must be 'Ed25519'",
    }, readme="# Case 09b — Wrong signing algorithm (Negative)\n\n`signing_algorithm` is `ES256` instead of `Ed25519`.\n",
       args=args, response_body=resp)

    # 09c: malformed public key — not valid base64 of 32 bytes
    r = build_l1(tool="echo", tool_call_id="call-bad-pk",
                 args=args, response_body=resp, sequence=0)
    r["public_key"] = "!!!not-base64!!!"
    # Re-signing would fail because verification uses this key; but sign_payload
    # uses the correct private key. The signature is over the (corrupt) receipt.
    r["signature"] = sign_payload(r)
    write_l1_case(group / "09c-malformed-public-key", r, expected={
        "verdict": "invalid", "reason": "public key is not valid base64",
    }, readme="# Case 09c — Malformed public key (Negative)\n\n`public_key` is not valid base64.\n",
       args=args, response_body=resp)

    write_text(group / "README.md", """# Case 09 — Identity Negatives

Tests key/algorithm/fingerprint binding.
""")


# ---------------------------------------------------------------------------
# 10: Chain negatives (4)
# ---------------------------------------------------------------------------

def _chain_receipt(seq, *, trace_id=TRACE_ID, prev_digest=None,
                   tool=None, tool_call_id=None, nonce=None):
    if tool is None:
        tool = f"step_{seq}"
    if tool_call_id is None:
        tool_call_id = f"call-chain-{seq}"
    args = {"seq": seq}
    resp = {"seq": seq, "ok": True}
    rc = {"run_id": f"run-{TRACE_ID}", "step": seq}
    if prev_digest is not None:
        rc["prev_receipt_digest"] = prev_digest
    r = build_l1(
        tool=tool, tool_call_id=tool_call_id, args=args, response_body=resp,
        sequence=seq, runtime_context=rc, trace_id=trace_id,
        timestamp=BASE_TS + seq,
        issued_at=BASE_TS + seq,
        expires_at=BASE_TS + seq + TTL,
        verified_at=BASE_TS + seq,
        nonce=nonce,
    )
    return r, args, resp, rc


def _write_chain_case(case_dir, receipts_data, expected, readme, chain_spec):
    case_dir.mkdir(parents=True, exist_ok=True)
    for idx, (r, args, resp, rc) in enumerate(receipts_data):
        fname = f"receipt-{idx+1}.json"
        write_json(case_dir / fname, r)
        si = {k: v for k, v in r.items() if k != "signature"}
        write_bytes(case_dir / f"signing-input-{idx+1}.jcs", canonical_json(si))
        write_bytes(case_dir / f"signature-{idx+1}.sig", base64.b64decode(r["signature"]))
        write_json(case_dir / f"tool-args-{idx+1}.json", args)
        write_json(case_dir / f"response-body-{idx+1}.json", resp)
        write_json(case_dir / f"runtime-context-{idx+1}.json", rc)
    write_text(case_dir / "public-key.b64", PUBLIC_KEY_B64 + "\n")
    write_json(case_dir / "chain.json", chain_spec)
    write_json(case_dir / "expected.json", expected)
    write_text(case_dir / "README.md", readme)


def gen_10_chain() -> None:
    group = VECTORS_DIR / "10-chain-negatives"

    # Build a valid chain of 3 to use as basis
    r0, a0, resp0, rc0 = _chain_receipt(0)
    d0 = l1_digest(r0)
    r1, a1, resp1, rc1 = _chain_receipt(1, prev_digest=d0)
    d1 = l1_digest(r1)
    r2, a2, resp2, rc2 = _chain_receipt(2, prev_digest=d1)

    # 10a: sequence gap — seq 0, 2 (skip 1)
    rg0, ag0, resg0, rcg0 = _chain_receipt(0)
    dg0 = l1_digest(rg0)
    rg2, ag2, resg2, rcg2 = _chain_receipt(2, prev_digest=dg0)
    _write_chain_case(
        group / "10a-sequence-gap",
        [(rg0, ag0, resg0, rcg0), (rg2, ag2, resg2, rcg2)],
        {"verdict": "invalid", "reason": "sequence gap"},
        "# Case 10a — Sequence gap (Negative)\n\nSequences 0 then 2 (1 is missing).\n",
        {"order": ["receipt-1.json", "receipt-2.json"], "first_sequence": 0,
         "expected_prev_digests": [None, dg0]},
    )

    # 10b: prev-hash mismatch — r2 points to wrong digest
    rb0, ab0, resb0, rcb0 = _chain_receipt(0)
    wrong_prev = "sha256:" + "a" * 64
    rb2, ab2, resb2, rcb2 = _chain_receipt(2, prev_digest=wrong_prev)
    _write_chain_case(
        group / "10b-prev-hash-mismatch",
        [(rb0, ab0, resb0, rcb0), (rb2, ab2, resb2, rcb2)],
        {"verdict": "invalid", "reason": "prev_hash mismatch"},
        "# Case 10b — Prev hash mismatch (Negative)\n\nreceipt-2's `prev_receipt_digest` does not match receipt-1's actual digest.\n",
        {"order": ["receipt-1.json", "receipt-2.json"], "first_sequence": 0,
         "expected_prev_digests": [None, l1_digest(rb0)]},
    )

    # 10c: trace-id mismatch
    rt0, at0, rest0, rct0 = _chain_receipt(0, trace_id=TRACE_ID)
    dt0 = l1_digest(rt0)
    rt2, at2, rest2, rct2 = _chain_receipt(2, trace_id="different-trace-id", prev_digest=dt0)
    _write_chain_case(
        group / "10c-trace-id-mismatch",
        [(rt0, at0, rest0, rct0), (rt2, at2, rest2, rct2)],
        {"verdict": "invalid", "reason": "trace_id differ"},
        "# Case 10c — Trace ID mismatch (Negative)\n\nReceipts in the chain have different `trace_id` values.\n",
        {"order": ["receipt-1.json", "receipt-2.json"], "first_sequence": 0,
         "expected_prev_digests": [None, dt0]},
    )

    # 10d: empty chain — single receipt with sequence=2 and no predecessor
    rd2, ad2, resd2, rcd2 = _chain_receipt(2)
    _write_chain_case(
        group / "10d-empty-chain",
        [(rd2, ad2, resd2, rcd2)],
        {"verdict": "invalid", "reason": "no predecessor receipt in chain"},
        "# Case 10d — Empty chain (Negative)\n\nA single receipt with sequence=2 but no predecessor provided.\n",
        {"order": ["receipt-1.json"], "first_sequence": 0,
         "expects_predecessor": True},
    )

    write_text(group / "README.md", """# Case 10 — Chain Negatives

Tests chain integrity: sequence contiguity, prev-hash linkage,
trace-id consistency, and empty-chain detection.
""")


# ---------------------------------------------------------------------------
# 11: Integrity negatives (3)
# ---------------------------------------------------------------------------

def gen_11_integrity() -> None:
    group = VECTORS_DIR / "11-integrity-negatives"
    args = {"account": "A-1", "amount": 100}
    resp = {"status": "ok", "txn": "T-1"}
    tool = "transfer"
    tcid = "call-integrity"
    request_envelope = {"tool": tool, "tool_call_id": tcid, "args": args}
    params_envelope = {"tool": tool, "param_keys": sorted(args.keys())}
    config_envelope = {
        "rule_version": RULE_VERSION, "issuer": ISSUER, "audience": AUDIENCE,
        "deployment_mode": DEPLOYMENT_MODE, "verifier_source_class": VERIFIER_SOURCE_CLASS,
        "receipt_ttl_seconds": TTL, "max_clock_skew": MAX_CLOCK_SKEW,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    }

    # 11a: request_hash mismatch
    r = build_l1(tool=tool, tool_call_id=tcid, args=args, response_body=resp, sequence=0)
    r["request_hash"] = "b" * 64
    r["signature"] = sign_payload(r)
    write_l1_case(group / "11a-request-hash-mismatch", r, expected={
        "verdict": "invalid", "reason": "request_hash mismatch",
    }, readme="# Case 11a — request_hash mismatch (Negative)\n\nThe declared `request_hash` does not match the request envelope.\n",
       args=args, response_body=resp, request_envelope=request_envelope)

    # 11b: params_hash mismatch
    r = build_l1(tool=tool, tool_call_id=tcid, args=args, response_body=resp, sequence=0)
    r["params_hash"] = "c" * 64
    r["signature"] = sign_payload(r)
    write_l1_case(group / "11b-params-hash-mismatch", r, expected={
        "verdict": "invalid", "reason": "params_hash mismatch",
    }, readme="# Case 11b — params_hash mismatch (Negative)\n\nThe declared `params_hash` does not match the params envelope.\n",
       args=args, response_body=resp, params_envelope=params_envelope)

    # 11c: config_hash mismatch
    r = build_l1(tool=tool, tool_call_id=tcid, args=args, response_body=resp, sequence=0)
    r["config_hash"] = "d" * 64
    r["signature"] = sign_payload(r)
    write_l1_case(group / "11c-config-hash-mismatch", r, expected={
        "verdict": "invalid", "reason": "config_hash mismatch",
    }, readme="# Case 11c — config_hash mismatch (Negative)\n\nThe declared `config_hash` does not match the config envelope.\n",
       args=args, response_body=resp, config_envelope=config_envelope)

    write_text(group / "README.md", """# Case 11 — Integrity Negatives

Tests that committed hashes (request/params/config) match their
respective payloads. Complements 05c (response_hash).
""")


# ---------------------------------------------------------------------------
# 12: Nonce / replay negatives (2)
# ---------------------------------------------------------------------------

def gen_12_nonce() -> None:
    group = VECTORS_DIR / "12-nonce-negatives"
    shared_nonce = "replayed-nonce-0001"

    # 12a: nonce replay — two receipts with same nonce in a chain
    r0, a0, resp0, rc0 = _chain_receipt(0, nonce=shared_nonce)
    d0 = l1_digest(r0)
    r1, a1, resp1, rc1 = _chain_receipt(1, prev_digest=d0, nonce=shared_nonce)
    _write_chain_case(
        group / "12a-nonce-replay",
        [(r0, a0, resp0, rc0), (r1, a1, resp1, rc1)],
        {"verdict": "invalid", "reason": "duplicate nonce detected across chain"},
        "# Case 12a — Nonce replay (Negative)\n\nTwo receipts in the same chain use the same nonce.\n",
        {"order": ["receipt-1.json", "receipt-2.json"], "first_sequence": 0,
         "expected_prev_digests": [None, d0]},
    )

    # 12b: empty nonce
    args = {"q": "test"}
    resp = {"ok": True}
    r = build_l1(tool="search", tool_call_id="call-empty-nonce",
                 args=args, response_body=resp, sequence=0, nonce="")
    write_l1_case(group / "12b-empty-nonce", r, expected={
        "verdict": "invalid", "reason": "nonce must be non-empty",
    }, readme="# Case 12b — Empty nonce (Negative)\n\n`nonce` is an empty string; required non-empty.\n",
       args=args, response_body=resp)

    write_text(group / "README.md", """# Case 12 — Nonce / Replay Negatives

Tests nonce uniqueness and presence.
""")


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
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            if fname == "manifest.json":
                continue
            rel = fpath.relative_to(VECTORS_DIR).as_posix()
            files[rel] = sha256_file(fpath)
    manifest = {
        "version": "1.4.0-conformance",
        "generated_by": "generate_vectors.py + generate_extended_vectors.py",
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
    gen_06_l2()
    gen_07_structure()
    gen_08_temporal()
    gen_09_identity()
    gen_10_chain()
    gen_11_integrity()
    gen_12_nonce()
    gen_manifest()
    print(f"Extended vectors generated in {VECTORS_DIR}")


if __name__ == "__main__":
    main()
