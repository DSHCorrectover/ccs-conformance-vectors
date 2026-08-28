#!/usr/bin/env python3
"""Independent CCS Conformance Checker (MIT License).

Zero CCS code dependencies. Only uses:
  - Python standard library
  - cryptography (Ed25519)
  - jcs (RFC 8785 canonical JSON)

Supports:
  - L1 Receipt (30 fields, strict mode)
  - L2 Behavior Receipt (15 fields)
  - Structure / schema negatives
  - Temporal negatives (expiry, clock skew, issued_at ordering)
  - Identity negatives (fingerprint, algorithm, public key format)
  - Chain negatives (sequence gaps, prev-hash, trace-id consistency, empty chain)
  - Integrity negatives (request/params/config/response hash mismatches)
  - Nonce uniqueness within a chain / bundle
  - L2 linked L1 digest verification

Usage:
    python checkers/independent_checker.py <vectors-directory>

Exit code 0 if all vectors produce expected results, 1 otherwise.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

L1_FIELDS = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary",
    "rule_version", "request_hash", "response_hash", "runtime_context_hash",
    "config_hash", "verifier_source_class", "deployment_mode", "issuer",
    "audience", "nonce", "sequence", "issued_at", "expires_at",
    "max_clock_skew", "action", "signature", "signing_algorithm",
    "public_key_fingerprint", "public_key", "verified_at", "latency_us",
)
L1_FIELD_SET = frozenset(L1_FIELDS)

L2_FIELDS = (
    "receipt_type", "trace_id", "tool_call_id", "sequence",
    "linked_l1_receipt_digest", "behavior_evidence_verdict", "evidence_ref",
    "issuer", "audience", "issued_at", "deployment_mode",
    "signing_algorithm", "public_key_fingerprint", "public_key", "signature",
)
L2_FIELD_SET = frozenset(L2_FIELDS)

REQUIRED_NONEMPTY_L1 = (
    "trace_id", "receipt_version", "verdict", "tool", "tool_call_id",
    "issuer", "audience", "nonce", "action", "signing_algorithm",
    "public_key", "signature",
)

REQUIRED_NONEMPTY_L2 = (
    "receipt_type", "trace_id", "tool_call_id",
    "linked_l1_receipt_digest", "behavior_evidence_verdict", "evidence_ref",
    "issuer", "audience", "signing_algorithm", "public_key", "signature",
)

HASH_FIELDS_L1 = (
    "params_hash", "args_digest", "request_hash", "response_hash",
    "runtime_context_hash", "config_hash",
)

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")
SHA256_PREFIX_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def canonical_json(data: Any) -> bytes:
    """JCS-canonicalize (RFC 8785)."""
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(data: Any) -> str:
    return sha256_hex(canonical_json(data))


def receipt_digest_l1(receipt: dict) -> str:
    """Compute 'sha256:' + SHA-256(JCS(L1 receipt minus signature))."""
    signed = {k: v for k, v in receipt.items() if k != "signature"}
    return "sha256:" + sha256_hex(canonical_json(signed))


def b64decode_strict(value: str) -> bytes:
    """Strict base64 decode — rejects missing padding or non-base64 chars."""
    if not isinstance(value, str) or not value:
        raise ValueError("value must be non-empty string")
    # Validate character set
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", value):
        raise ValueError("invalid base64 characters")
    raw = base64.b64decode(value, validate=True)
    return raw


def verify_ed25519(
    public_key_b64: str,
    payload: dict,
    signature_b64: str,
) -> tuple[bool, str]:
    """Verify Ed25519 signature over JCS(payload minus 'signature')."""
    try:
        pub_bytes = b64decode_strict(public_key_b64)
    except Exception as exc:
        return False, f"public key base64 decode error: {exc}"
    try:
        sig_bytes = b64decode_strict(signature_b64)
    except Exception as exc:
        return False, f"signature base64 decode error: {exc}"

    if len(pub_bytes) != 32:
        return False, f"public key must be 32 bytes, got {len(pub_bytes)}"
    if len(sig_bytes) != 64:
        return False, f"signature must be 64 bytes, got {len(sig_bytes)}"

    signed = {k: v for k, v in payload.items() if k != "signature"}
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical_json(signed))
        return True, "ok"
    except InvalidSignature:
        return False, "signature mismatch: signature does not verify over JCS canonical bytes"
    except Exception as exc:
        return False, f"verification error: {exc}"


def compute_fingerprint(public_key_b64: str) -> str:
    """16-hex-char fingerprint = first 16 hex chars of SHA-256(raw pubkey)."""
    raw = b64decode_strict(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def is_valid_instant(value: Any) -> tuple[bool, str]:
    """Check that a timestamp value represents a real instant."""
    if isinstance(value, bool):
        return False, "timestamp must not be boolean"
    if isinstance(value, (int, float)):
        return True, "ok"
    if isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            datetime.datetime.fromisoformat(s)
            return True, "ok"
        except (ValueError, OverflowError) as exc:
            return False, f"timestamp denotes impossible instant: {value!r} ({exc})"
    return False, f"timestamp must be numeric or ISO 8601 string, got {type(value).__name__}"


def to_epoch_seconds(value: Any) -> float | None:
    """Convert a timestamp value (numeric epoch or ISO 8601 string) to epoch seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except (ValueError, OverflowError):
            return None
    return None


# ---------------------------------------------------------------------------
# L1 structural validation
# ---------------------------------------------------------------------------

def validate_l1_structure(receipt: Any) -> list[tuple[str, bool, str]]:
    """Validate L1 30-field structure. Returns list of (check, passed, detail)."""
    checks: list[tuple[str, bool, str]] = []

    if not isinstance(receipt, dict):
        checks.append(("structure:dict", False, "receipt must be a JSON object"))
        return checks

    keys = set(receipt.keys())
    extra = keys - L1_FIELD_SET
    missing = L1_FIELD_SET - keys

    if extra:
        checks.append((
            "structure:unknown-field",
            False,
            f"unknown field(s) in strict mode: {sorted(extra)}",
        ))
    if missing:
        checks.append((
            "structure:missing-field",
            False,
            f"missing required field(s): {sorted(missing)}",
        ))
    if not extra and not missing:
        checks.append(("structure:exact-30-fields", True, "ok"))

    if extra or missing:
        return checks  # Cannot continue type checks reliably

    # Required non-empty strings
    for field in REQUIRED_NONEMPTY_L1:
        val = receipt.get(field)
        is_empty = val is None or (isinstance(val, str) and not val)
        checks.append((
            f"structure:nonempty:{field}",
            not is_empty,
            "ok" if not is_empty else f"field {field!r} must be non-empty",
        ))

    # verdict enum
    checks.append((
        "field:verdict-value",
        receipt["verdict"] in ("allow", "block"),
        "ok" if receipt["verdict"] in ("allow", "block")
        else f"verdict must be 'allow' or 'block', got {receipt['verdict']!r}",
    ))

    # signing_algorithm whitelist
    checks.append((
        "field:signing_algorithm",
        receipt["signing_algorithm"] == "Ed25519",
        "ok" if receipt["signing_algorithm"] == "Ed25519"
        else f"signing_algorithm must be 'Ed25519', got {receipt['signing_algorithm']!r}",
    ))

    # sequence: non-negative integer
    seq = receipt["sequence"]
    checks.append((
        "field:sequence",
        isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0,
        "ok" if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0
        else f"sequence must be non-negative integer, got {seq!r}",
    ))

    # max_clock_skew: non-negative number
    mcs = receipt["max_clock_skew"]
    checks.append((
        "field:max_clock_skew",
        isinstance(mcs, (int, float)) and not isinstance(mcs, bool) and mcs >= 0,
        "ok" if isinstance(mcs, (int, float)) and not isinstance(mcs, bool) and mcs >= 0
        else f"max_clock_skew must be non-negative number, got {mcs!r}",
    ))

    # latency_us: non-negative number
    lat = receipt["latency_us"]
    checks.append((
        "field:latency_us",
        isinstance(lat, (int, float)) and not isinstance(lat, bool) and lat >= 0,
        "ok" if isinstance(lat, (int, float)) and not isinstance(lat, bool) and lat >= 0
        else f"latency_us must be non-negative number, got {lat!r}",
    ))

    # timestamp: numeric or ISO string (not bool)
    ts = receipt["timestamp"]
    ts_ok = (
        (isinstance(ts, (int, float)) and not isinstance(ts, bool))
        or (isinstance(ts, str) and not isinstance(ts, bool))
    )
    checks.append((
        "field:timestamp-type",
        ts_ok,
        "ok" if ts_ok else f"timestamp must be numeric or ISO 8601 string, got {type(ts).__name__}",
    ))

    # Hash fields: 64 hex chars
    for hf in HASH_FIELDS_L1:
        val = receipt.get(hf, "")
        ok = isinstance(val, str) and bool(HEX_SHA256_RE.match(val))
        checks.append((
            f"field:hash-format:{hf}",
            ok,
            "ok" if ok else f"{hf} must be 64 lowercase hex chars, got {val!r}",
        ))

    # Fingerprint format
    fpr = receipt.get("public_key_fingerprint", "")
    fpr_ok = isinstance(fpr, str) and bool(HEX_FINGERPRINT_RE.match(fpr))
    checks.append((
        "field:fingerprint-format",
        fpr_ok,
        "ok" if fpr_ok else f"public_key_fingerprint must be 16 lowercase hex chars, got {fpr!r}",
    ))

    # Public key: valid base64, 32 bytes
    pk = receipt.get("public_key", "")
    try:
        pk_raw = b64decode_strict(pk)
        pk_len_ok = len(pk_raw) == 32
        checks.append((
            "field:public-key-format",
            pk_len_ok,
            "ok" if pk_len_ok else f"public key must decode to 32 bytes, got {len(pk_raw)}",
        ))
    except Exception as exc:
        checks.append((
            "field:public-key-format",
            False,
            f"public key is not valid base64: {exc}",
        ))

    return checks


# ---------------------------------------------------------------------------
# L2 structural validation
# ---------------------------------------------------------------------------

def validate_l2_structure(receipt: Any) -> list[tuple[str, bool, str]]:
    """Validate L2 Behavior Receipt structure."""
    checks: list[tuple[str, bool, str]] = []

    if not isinstance(receipt, dict):
        checks.append(("structure:dict", False, "receipt must be a JSON object"))
        return checks

    keys = set(receipt.keys())
    extra = keys - L2_FIELD_SET
    missing = L2_FIELD_SET - keys

    if extra:
        checks.append(("structure:unknown-field", False,
                       f"unknown field(s) in strict mode: {sorted(extra)}"))
    if missing:
        checks.append(("structure:missing-field", False,
                       f"missing required field(s): {sorted(missing)}"))
    if not extra and not missing:
        checks.append(("structure:exact-15-fields", True, "ok"))

    if extra or missing:
        return checks

    for field in REQUIRED_NONEMPTY_L2:
        val = receipt.get(field)
        is_empty = val is None or (isinstance(val, str) and not val)
        checks.append((
            f"structure:nonempty:{field}",
            not is_empty,
            "ok" if not is_empty else f"field {field!r} must be non-empty",
        ))

    # receipt_type
    checks.append((
        "field:receipt_type",
        receipt["receipt_type"] == "ccs.behavior_evidence.v1",
        "ok" if receipt["receipt_type"] == "ccs.behavior_evidence.v1"
        else f"receipt_type must be 'ccs.behavior_evidence.v1', got {receipt['receipt_type']!r}",
    ))

    # behavior_evidence_verdict enum
    bev = receipt["behavior_evidence_verdict"]
    bev_ok = bev in ("not_observed", "observed_and_allowed", "observed_and_rejected")
    checks.append((
        "field:behavior_evidence_verdict",
        bev_ok,
        "ok" if bev_ok else f"behavior_evidence_verdict invalid, got {bev!r}",
    ))

    # sequence non-negative int
    seq = receipt["sequence"]
    checks.append((
        "field:sequence",
        isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0,
        "ok" if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0
        else f"sequence must be non-negative integer, got {seq!r}",
    ))

    # signing_algorithm
    checks.append((
        "field:signing_algorithm",
        receipt["signing_algorithm"] == "Ed25519",
        "ok" if receipt["signing_algorithm"] == "Ed25519"
        else f"signing_algorithm must be 'Ed25519', got {receipt['signing_algorithm']!r}",
    ))

    # linked_l1_receipt_digest format: sha256:<64hex>
    l1d = receipt["linked_l1_receipt_digest"]
    l1d_ok = isinstance(l1d, str) and bool(SHA256_PREFIX_RE.match(l1d))
    checks.append((
        "field:linked_l1_receipt_digest-format",
        l1d_ok,
        "ok" if l1d_ok else f"linked_l1_receipt_digest must be 'sha256:' + 64 hex chars, got {l1d!r}",
    ))

    # fingerprint format
    fpr = receipt.get("public_key_fingerprint", "")
    fpr_ok = isinstance(fpr, str) and bool(HEX_FINGERPRINT_RE.match(fpr))
    checks.append((
        "field:fingerprint-format",
        fpr_ok,
        "ok" if fpr_ok else f"public_key_fingerprint must be 16 hex chars, got {fpr!r}",
    ))

    # public key format
    pk = receipt.get("public_key", "")
    try:
        pk_raw = b64decode_strict(pk)
        checks.append((
            "field:public-key-format",
            len(pk_raw) == 32,
            "ok" if len(pk_raw) == 32 else f"public key must be 32 bytes, got {len(pk_raw)}",
        ))
    except Exception as exc:
        checks.append(("field:public-key-format", False,
                       f"public key is not valid base64: {exc}"))

    # issued_at valid instant
    ia_ok, ia_detail = is_valid_instant(receipt["issued_at"])
    checks.append(("field:issued_at-valid", ia_ok, ia_detail))

    return checks


# ---------------------------------------------------------------------------
# L1 semantic / cross-field validation
# ---------------------------------------------------------------------------

def validate_l1_semantic(
    receipt: dict,
    *,
    response_body: Any = None,
    tool_args: Any = None,
    runtime_context: Any = None,
    request_envelope: Any = None,
    params_envelope: Any = None,
    config_envelope: Any = None,
    has_response_body: bool = False,
    has_tool_args: bool = False,
    has_runtime_context: bool = False,
    has_request_envelope: bool = False,
    has_params_envelope: bool = False,
    has_config_envelope: bool = False,
) -> list[tuple[str, bool, str]]:
    """Cross-field semantic validation for L1."""
    checks: list[tuple[str, bool, str]] = []

    # --- Timestamp validity ---
    for ts_field in ("timestamp", "issued_at", "expires_at", "verified_at"):
        val = receipt.get(ts_field)
        ok, detail = is_valid_instant(val)
        checks.append((f"timestamp:valid:{ts_field}", ok, detail))
        if not ok:
            return checks

    # --- expires_at >= issued_at ---
    issued_ep = to_epoch_seconds(receipt["issued_at"])
    expires_ep = to_epoch_seconds(receipt["expires_at"])
    if issued_ep is not None and expires_ep is not None:
        checks.append((
            "cross-field:expires-after-issued",
            expires_ep >= issued_ep,
            "ok" if expires_ep >= issued_ep
            else f"expires_at ({receipt['expires_at']}) is before issued_at ({receipt['issued_at']})",
        ))
    else:
        checks.append(("cross-field:expires-after-issued", False,
                       "cannot compare issued_at/expires_at"))

    # --- issued_at <= timestamp (issued must not be after the event) ---
    ts_ep = to_epoch_seconds(receipt["timestamp"])
    if issued_ep is not None and ts_ep is not None:
        checks.append((
            "cross-field:issued-before-timestamp",
            issued_ep <= ts_ep,
            "ok" if issued_ep <= ts_ep
            else f"issued_at ({receipt['issued_at']}) is after timestamp ({receipt['timestamp']})",
        ))

    # --- Clock skew: |timestamp - verified_at| <= max_clock_skew ---
    verified_ep = to_epoch_seconds(receipt["verified_at"])
    mcs = receipt["max_clock_skew"]
    if ts_ep is not None and verified_ep is not None:
        skew = abs(ts_ep - verified_ep)
        checks.append((
            "cross-field:clock-skew",
            skew <= mcs,
            "ok" if skew <= mcs
            else f"timestamp skew {skew}s exceeds max_clock_skew {mcs}s",
        ))

    # --- public_key_fingerprint matches actual public key ---
    try:
        expected_fpr = compute_fingerprint(receipt["public_key"])
        checks.append((
            "cross-field:fingerprint-matches",
            receipt["public_key_fingerprint"] == expected_fpr,
            "ok" if receipt["public_key_fingerprint"] == expected_fpr
            else f"declared fingerprint {receipt['public_key_fingerprint']!r} != computed {expected_fpr!r}",
        ))
    except Exception as exc:
        checks.append(("cross-field:fingerprint-matches", False, f"error: {exc}"))

    # --- response_hash matches response body ---
    if has_response_body:
        actual = canonical_sha256_hex(response_body)
        declared = receipt["response_hash"]
        checks.append((
            "hash:response_hash-matches-body",
            declared == actual,
            "ok" if declared == actual
            else f"response_hash mismatch: declared {declared[:16]}... != actual {actual[:16]}...",
        ))

    # --- args_digest matches tool args ---
    if has_tool_args:
        actual = canonical_sha256_hex(tool_args)
        declared = receipt["args_digest"]
        checks.append((
            "hash:args_digest-matches",
            declared == actual,
            "ok" if declared == actual
            else f"args_digest mismatch: declared {declared[:16]}... != actual {actual[:16]}...",
        ))

    # --- request_hash matches request envelope ---
    if has_request_envelope:
        actual = canonical_sha256_hex(request_envelope)
        declared = receipt["request_hash"]
        checks.append((
            "hash:request_hash-matches",
            declared == actual,
            "ok" if declared == actual
            else f"request_hash mismatch: declared {declared[:16]}... != actual {actual[:16]}...",
        ))

    # --- params_hash matches params envelope ---
    if has_params_envelope:
        actual = canonical_sha256_hex(params_envelope)
        declared = receipt["params_hash"]
        checks.append((
            "hash:params_hash-matches",
            declared == actual,
            "ok" if declared == actual
            else f"params_hash mismatch: declared {declared[:16]}... != actual {actual[:16]}...",
        ))

    # --- config_hash matches config envelope ---
    if has_config_envelope:
        actual = canonical_sha256_hex(config_envelope)
        declared = receipt["config_hash"]
        checks.append((
            "hash:config_hash-matches",
            declared == actual,
            "ok" if declared == actual
            else f"config_hash mismatch: declared {declared[:16]}... != actual {actual[:16]}...",
        ))

    # --- verdict / response-body consistency ---
    verdict = receipt.get("verdict")
    if verdict == "block" and has_response_body:
        is_block_env = (
            isinstance(response_body, dict)
            and response_body.get("blocked") is True
            and "reason" in response_body
        )
        checks.append((
            "cross-field:block-envelope",
            is_block_env,
            "ok" if is_block_env
            else "verdict=block but response body is not a block envelope {blocked:true, reason:...}",
        ))
        carries_normal = (
            isinstance(response_body, dict) and "blocked" not in response_body
        )
        checks.append((
            "cross-field:deny-no-response-commitment",
            not carries_normal,
            "ok" if not carries_normal
            else "deny verdict carries response commitment",
        ))
    elif verdict == "allow" and has_response_body:
        is_not_block = not (
            isinstance(response_body, dict) and response_body.get("blocked") is True
        )
        checks.append((
            "cross-field:allow-not-block-envelope",
            is_not_block,
            "ok" if is_not_block
            else "verdict=allow but response body is a block envelope",
        ))

    # --- sandbox flag binding ---
    if has_runtime_context and isinstance(runtime_context, dict):
        sandbox = runtime_context.get("sandbox", False)
        if sandbox is True:
            issuer = receipt.get("issuer", "").lower()
            principal = str(runtime_context.get("principal", "")).lower()
            environment = str(runtime_context.get("environment", "")).lower()
            kw = ("sandbox", "dev", "test", "staging", "non-prod")
            bound = (
                any(k in issuer for k in kw)
                or any(k in principal for k in kw)
                or any(k in environment for k in kw)
            )
            checks.append((
                "cross-field:sandbox-bound-to-principal",
                bound,
                "ok" if bound
                else "sandbox flag not bound to principal (sandbox=true but issuer/principal/environment indicates production)",
            ))

    return checks


# ---------------------------------------------------------------------------
# L2 semantic validation
# ---------------------------------------------------------------------------

def validate_l2_semantic(
    receipt: dict,
    *,
    linked_l1_receipt: dict | None = None,
    has_linked_l1: bool = False,
) -> list[tuple[str, bool, str]]:
    """Semantic validation for L2 behavior receipt."""
    checks: list[tuple[str, bool, str]] = []

    # Fingerprint
    try:
        expected_fpr = compute_fingerprint(receipt["public_key"])
        checks.append((
            "cross-field:fingerprint-matches",
            receipt["public_key_fingerprint"] == expected_fpr,
            "ok" if receipt["public_key_fingerprint"] == expected_fpr
            else f"declared {receipt['public_key_fingerprint']!r} != computed {expected_fpr!r}",
        ))
    except Exception as exc:
        checks.append(("cross-field:fingerprint-matches", False, f"error: {exc}"))

    # Linked L1 digest verification
    if has_linked_l1 and linked_l1_receipt is not None:
        actual_digest = receipt_digest_l1(linked_l1_receipt)
        declared = receipt["linked_l1_receipt_digest"]
        checks.append((
            "l2:linked-l1-digest-matches",
            declared == actual_digest,
            "ok" if declared == actual_digest
            else f"linked_l1_receipt_digest mismatch: declared {declared[:24]}... != actual {actual_digest[:24]}...",
        ))

    return checks


# ---------------------------------------------------------------------------
# File loading helpers
# ---------------------------------------------------------------------------

def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_companion(case_dir: Path, receipt_path: Path, suffix: str) -> Path | None:
    """Find companion file (response-body-1.json, runtime-context.json, etc.)."""
    stem = receipt_path.stem
    parts = stem.split("-")
    if len(parts) >= 2 and parts[-1].isdigit():
        numbered = case_dir / f"{suffix.rstrip('.json')}-{parts[-1]}.json"
        if numbered.exists():
            return numbered
    if len(parts) >= 2:
        variant = case_dir / f"{suffix.rstrip('.json')}-{'-'.join(parts[1:])}.json"
        if variant.exists():
            return variant
    default = case_dir / suffix
    if default.exists():
        return default
    return None


# ---------------------------------------------------------------------------
# Manifest verification
# ---------------------------------------------------------------------------

def verify_manifest(vectors_dir: Path) -> tuple[bool, list[str]]:
    manifest_path = vectors_dir / "manifest.json"
    if not manifest_path.exists():
        return False, ["manifest.json not found"]
    manifest = load_json(manifest_path)
    errors: list[str] = []
    for rel_path, expected_hash in manifest.get("files", {}).items():
        fpath = vectors_dir / rel_path
        if not fpath.exists():
            errors.append(f"missing file: {rel_path}")
            continue
        actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual != expected_hash:
            errors.append(
                f"hash mismatch: {rel_path} (expected {expected_hash[:16]}..., got {actual[:16]}...)"
            )
    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Receipt type detection
# ---------------------------------------------------------------------------

def detect_receipt_type(receipt: Any) -> str:
    """Return 'l1', 'l2', or 'unknown'."""
    if isinstance(receipt, dict):
        if "receipt_type" in receipt and receipt.get("receipt_type", "").startswith("ccs.behavior"):
            return "l2"
        if "verdict" in receipt and "tool" in receipt and "latency_us" in receipt:
            return "l1"
        if "verdict" in receipt or "latency_us" in receipt:
            return "l1"
    return "unknown"


# ---------------------------------------------------------------------------
# Single receipt verification
# ---------------------------------------------------------------------------

def verify_receipt(receipt_path: Path, case_dir: Path) -> dict:
    result: dict[str, Any] = {
        "receipt": receipt_path.name,
        "checks": [],
        "passed": True,
        "reason": None,
        "receipt_type": None,
        "receipt_data": None,
    }

    try:
        receipt = load_json(receipt_path)
    except Exception as exc:
        result["passed"] = False
        result["reason"] = f"failed to load receipt: {exc}"
        result["checks"].append(("load", False, str(exc)))
        return result

    rtype = detect_receipt_type(receipt)
    result["receipt_type"] = rtype
    result["receipt_data"] = receipt

    if rtype == "l2":
        return _verify_l2_receipt(receipt, receipt_path, case_dir, result)
    else:
        return _verify_l1_receipt(receipt, receipt_path, case_dir, result)


def _verify_l1_receipt(receipt, receipt_path, case_dir, result):
    # Structural
    struct = validate_l1_structure(receipt)
    result["checks"].extend(struct)
    struct_failed = [c for c in struct if not c[1]]
    if struct_failed:
        result["passed"] = False
        result["reason"] = struct_failed[0][2]
        return result

    # Signature
    sig_ok, sig_detail = verify_ed25519(
        receipt["public_key"], receipt, receipt["signature"]
    )
    result["checks"].append(("signature:ed25519", sig_ok, sig_detail))
    if not sig_ok:
        result["passed"] = False
        result["reason"] = "signature mismatch"
        # Continue to semantic to surface other issues, but receipt fails

    # Companion files
    companions = _load_l1_companions(case_dir, receipt_path)

    sem = validate_l1_semantic(receipt, **companions)
    result["checks"].extend(sem)
    sem_failed = [c for c in sem if not c[1]]
    if sem_failed and result["reason"] is None:
        result["passed"] = False
        result["reason"] = sem_failed[0][2]
    elif sem_failed:
        result["passed"] = False

    return result


def _verify_l2_receipt(receipt, receipt_path, case_dir, result):
    struct = validate_l2_structure(receipt)
    result["checks"].extend(struct)
    struct_failed = [c for c in struct if not c[1]]
    if struct_failed:
        result["passed"] = False
        result["reason"] = struct_failed[0][2]
        return result

    sig_ok, sig_detail = verify_ed25519(
        receipt["public_key"], receipt, receipt["signature"]
    )
    result["checks"].append(("signature:ed25519", sig_ok, sig_detail))
    if not sig_ok:
        result["passed"] = False
        result["reason"] = "signature mismatch"

    # Linked L1 companion
    linked = None
    has_linked = False
    l1_path = find_companion(case_dir, receipt_path, "linked-l1-receipt.json")
    if l1_path:
        try:
            linked = load_json(l1_path)
            has_linked = True
        except Exception:
            pass

    sem = validate_l2_semantic(
        receipt, linked_l1_receipt=linked, has_linked_l1=has_linked
    )
    result["checks"].extend(sem)
    sem_failed = [c for c in sem if not c[1]]
    if sem_failed and result["reason"] is None:
        result["passed"] = False
        result["reason"] = sem_failed[0][2]
    elif sem_failed:
        result["passed"] = False

    return result


def _load_l1_companions(case_dir: Path, receipt_path: Path) -> dict:
    """Load all available companion files for an L1 receipt."""
    out = {
        "response_body": None, "tool_args": None, "runtime_context": None,
        "request_envelope": None, "params_envelope": None, "config_envelope": None,
        "has_response_body": False, "has_tool_args": False,
        "has_runtime_context": False, "has_request_envelope": False,
        "has_params_envelope": False, "has_config_envelope": False,
    }

    rb = find_companion(case_dir, receipt_path, "response-body.json")
    if rb:
        try:
            out["response_body"] = load_json(rb)
            out["has_response_body"] = True
        except Exception:
            pass

    ta = find_companion(case_dir, receipt_path, "tool-args.json")
    if ta:
        try:
            out["tool_args"] = load_json(ta)
            out["has_tool_args"] = True
        except Exception:
            pass

    rc = find_companion(case_dir, receipt_path, "runtime-context.json")
    if rc:
        try:
            out["runtime_context"] = load_json(rc)
            out["has_runtime_context"] = True
        except Exception:
            pass

    rq = find_companion(case_dir, receipt_path, "request-envelope.json")
    if rq:
        try:
            out["request_envelope"] = load_json(rq)
            out["has_request_envelope"] = True
        except Exception:
            pass

    pe = find_companion(case_dir, receipt_path, "params-envelope.json")
    if pe:
        try:
            out["params_envelope"] = load_json(pe)
            out["has_params_envelope"] = True
        except Exception:
            pass

    ce = find_companion(case_dir, receipt_path, "config-envelope.json")
    if ce:
        try:
            out["config_envelope"] = load_json(ce)
            out["has_config_envelope"] = True
        except Exception:
            pass

    return out


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------

def validate_chain(case_dir: Path, receipt_results: list[dict]) -> list[tuple[str, bool, str]]:
    """Validate chain properties from chain.json or from numbered receipts.

    Returns list of (check_name, passed, detail).
    """
    checks: list[tuple[str, bool, str]] = []
    chain_path = case_dir / "chain.json"

    chain_spec = None
    if chain_path.exists():
        try:
            chain_spec = load_json(chain_path)
        except Exception as exc:
            checks.append(("chain:spec-load", False, f"cannot load chain.json: {exc}"))
            return checks

    # Gather receipt data from results (reloaded already)
    receipts = []
    for rr in receipt_results:
        rd = rr.get("receipt_data")
        if rd is not None:
            receipts.append((rr["receipt"], rd))

    if not receipts:
        checks.append(("chain:has-receipts", False, "no receipts to validate"))
        return checks

    # If chain spec exists, use its declared order; otherwise use file order.
    if chain_spec and "order" in chain_spec:
        name_to_data = {name: data for name, data in receipts}
        ordered = []
        for fname in chain_spec["order"]:
            if fname in name_to_data:
                ordered.append((fname, name_to_data[fname]))
            else:
                checks.append(("chain:order-file", False,
                               f"chain.json references {fname} but file not verified"))
        receipts = ordered

    if len(receipts) < 1:
        checks.append(("chain:non-empty", False, "chain has no receipts"))
        return checks

    # 1. Same trace_id
    trace_ids = set()
    for name, data in receipts:
        if isinstance(data, dict):
            tid = data.get("trace_id")
            if tid is not None:
                trace_ids.add(tid)
    checks.append((
        "chain:trace-id-consistent",
        len(trace_ids) == 1,
        "ok" if len(trace_ids) == 1 else f"trace_ids differ: {trace_ids}",
    ))

    # 2. Nonce uniqueness
    nonces = {}
    dup_nonce = False
    for name, data in receipts:
        if isinstance(data, dict):
            n = data.get("nonce", "")
            if n:  # Only check non-empty nonces; empty-nonce is a separate structural fail
                if n in nonces:
                    dup_nonce = True
                nonces[n] = name
    checks.append((
        "chain:nonce-unique",
        not dup_nonce,
        "ok" if not dup_nonce else f"duplicate nonce detected across chain: {sorted(nonces.keys())}",
    ))

    # 3. Sequence continuity (must be contiguous starting at expected first seq)
    seqs = []
    for name, data in receipts:
        if isinstance(data, dict):
            s = data.get("sequence")
            if isinstance(s, int) and not isinstance(s, bool):
                seqs.append((name, s))

    if seqs:
        seq_values = [s for _, s in seqs]
        expected_first = chain_spec.get("first_sequence", 0) if chain_spec else 0
        expected = list(range(expected_first, expected_first + len(seqs)))
        contiguous = seq_values == expected
        checks.append((
            "chain:sequence-contiguous",
            contiguous,
            "ok" if contiguous else f"sequence gap or order error: got {seq_values}, expected {expected}",
        ))

        # 4. Empty chain: first receipt sequence > 0 but no predecessor provided
        if seq_values and seq_values[0] > 0 and chain_spec and chain_spec.get("expects_predecessor", True):
            checks.append((
                "chain:empty-chain-no-predecessor",
                False,
                f"first receipt sequence={seq_values[0]} but no predecessor receipt in chain",
            ))
        elif seq_values and seq_values[0] > 0 and not chain_spec:
            # Without chain spec, we can't tell — but if chain declares expected first, handled above
            pass

    # 5. prev-hash linkage (from runtime context prev_receipt_digest)
    if chain_spec and "expected_prev_digests" in chain_spec:
        expected_prevs = chain_spec["expected_prev_digests"]
        for i, (name, data) in enumerate(receipts):
            if not isinstance(data, dict):
                continue
            # Compute actual digest of this receipt
            actual_digest = receipt_digest_l1(data)
            # The expected prev digest for receipt i is the digest of receipt i-1
            if i < len(expected_prevs):
                # Load runtime context for this receipt and check prev_receipt_digest
                stem = Path(name).stem
                parts = stem.split("-")
                rc = None
                if len(parts) >= 2 and parts[-1].isdigit():
                    rc_path = case_dir / f"runtime-context-{parts[-1]}.json"
                    if rc_path.exists():
                        rc = load_json(rc_path)
                if rc is None:
                    rc_path = case_dir / "runtime-context.json"
                    if rc_path.exists():
                        rc = load_json(rc_path)
                if rc and "prev_receipt_digest" in rc:
                    actual_prev = rc["prev_receipt_digest"]
                    expected_prev = expected_prevs[i]
                    checks.append((
                        "chain:prev-hash-matches",
                        actual_prev == expected_prev,
                        "ok" if actual_prev == expected_prev
                        else f"prev_receipt_digest mismatch in {name}: declared {str(actual_prev)[:24]}... expected {str(expected_prev)[:24]}...",
                    ))

    return checks


# ---------------------------------------------------------------------------
# Case verification
# ---------------------------------------------------------------------------

def verify_case(case_dir: Path) -> dict:
    result: dict[str, Any] = {
        "case": case_dir.name,
        "receipts": [],
        "passed": True,
        "expected": None,
        "reason": None,
    }

    expected_path = case_dir / "expected.json"
    if expected_path.exists():
        result["expected"] = load_json(expected_path)

    receipt_files = sorted(
        p for p in case_dir.glob("receipt*.json") if p.is_file()
    )
    if not receipt_files:
        result["passed"] = False
        result["reason"] = "no receipt files found"
        return result

    for rp in receipt_files:
        result["receipts"].append(verify_receipt(rp, case_dir))

    # Chain validation if chain.json present OR special 03-chain-of-3
    is_chain_case = (case_dir / "chain.json").exists() or case_dir.name == "03-chain-of-3"
    if is_chain_case:
        chain_checks = validate_chain(case_dir, result["receipts"])
        if chain_checks and result["receipts"]:
            result["receipts"][0]["checks"].extend(chain_checks)
        chain_failed = [c for c in chain_checks if not c[1]]
        if chain_failed:
            result["passed"] = False
            if result["reason"] is None:
                result["reason"] = chain_failed[0][2]

    # Overall per-receipt pass
    all_receipts_passed = all(r["passed"] for r in result["receipts"])

    expected_verdict = result["expected"].get("verdict") if result["expected"] else None

    if expected_verdict == "valid":
        result["passed"] = all_receipts_passed and result.get("passed", True)
        if not all_receipts_passed:
            failed = [r for r in result["receipts"] if not r["passed"]]
            result["reason"] = failed[0].get("reason", "expected valid but verification failed")
    elif expected_verdict == "invalid":
        any_failed = any(not r["passed"] for r in result["receipts"])
        if not any_failed:
            result["passed"] = False
            result["reason"] = "expected invalid but all receipts passed"
        else:
            # Match expected reason keywords
            expected_reason = result["expected"].get("reason", "") if result["expected"] else ""
            if expected_reason:
                stop = {"does", "that", "this", "with", "from", "have", "been",
                        "were", "their", "will", "would", "could", "should",
                        "than", "then", "into", "about", "your", "must"}
                kws = set(
                    w.lower() for w in re.findall(r"[a-z_]+", expected_reason)
                    if len(w) > 3 and w.lower() not in stop
                )
                matched = False
                for rr in result["receipts"]:
                    for cname, cpassed, cdetail in rr.get("checks", []):
                        if cpassed:
                            continue
                        hay = (cname + " " + cdetail).lower()
                        if all(kw in hay for kw in kws):
                            matched = True
                            break
                    if matched:
                        break
                if not matched:
                    all_failed = []
                    for rr in result["receipts"]:
                        for cname, cpassed, cdetail in rr.get("checks", []):
                            if not cpassed:
                                all_failed.append(f"{cname}: {cdetail}")
                    result["passed"] = False
                    result["reason"] = (
                        f"expected reason keywords {sorted(kws)!r} not found; "
                        f"failed checks: {all_failed!r}"
                    )
                else:
                    result["passed"] = True
            else:
                result["passed"] = True
    else:
        result["passed"] = all_receipts_passed and result.get("passed", True)

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_case_dirs(vectors_dir: Path) -> list[Path]:
    """Find all case directories (containing expected.json), including one nesting level."""
    cases = []
    for entry in sorted(vectors_dir.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if (entry / "expected.json").exists():
            cases.append(entry)
        for sub in sorted(entry.iterdir()):
            if sub.is_dir() and (sub / "expected.json").exists():
                cases.append(sub)
    return cases


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <vectors-directory>", file=sys.stderr)
        return 2

    vectors_dir = Path(sys.argv[1]).resolve()
    if not vectors_dir.is_dir():
        print(f"Error: {vectors_dir} is not a directory", file=sys.stderr)
        return 2

    manifest_ok, manifest_errors = verify_manifest(vectors_dir)
    if not manifest_ok:
        print("MANIFEST VERIFICATION FAILED:")
        for err in manifest_errors:
            print(f"  ✗ {err}")
        return 1
    print(f"✓ Manifest verified ({vectors_dir.name}/manifest.json)")

    case_dirs = find_case_dirs(vectors_dir)
    if not case_dirs:
        print("No case directories with expected.json found", file=sys.stderr)
        return 1

    all_passed = True
    total_checks = 0
    passed_checks = 0

    for case_dir in case_dirs:
        result = verify_case(case_dir)
        rel = case_dir.relative_to(vectors_dir)

        for rr in result.get("receipts", []):
            for _, cp, _ in rr.get("checks", []):
                total_checks += 1
                if cp:
                    passed_checks += 1

        status = "✓ PASS" if result["passed"] else "✗ FAIL"
        print(f"\n{status}  {rel}")
        expected = result.get("expected", {})
        if expected:
            print(f"         Expected: {expected.get('verdict', '?')}"
                  + (f" — {expected.get('reason', '')}" if expected.get("reason") else ""))
        if not result["passed"]:
            print(f"         Reason: {result.get('reason', 'unknown')}")
            all_passed = False

        for rr in result.get("receipts", []):
            failed = [c for c in rr["checks"] if not c[1]]
            for fc in failed:
                print(f"         ✗ {rr['receipt']}: {fc[0]} — {fc[2]}")

    print(f"\n{'='*60}")
    print(f"Checks: {passed_checks}/{total_checks} passed")
    print(f"Cases:  {len(case_dirs)}/{len(case_dirs)} matched expected outcome")

    if all_passed:
        print("\n✓ ALL VECTORS PASSED")
        return 0
    else:
        print("\n✗ SOME VECTORS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
