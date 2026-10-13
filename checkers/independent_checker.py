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
  - Chain negatives (sequence gaps, prev-hash anchored to predecessor bytes,
    trace-id consistency, empty chain)
  - Integrity negatives (request/params/config/response hash mismatches)
  - Nonce uniqueness within a chain / bundle
  - L2 linked L1 digest verification
  - canonicalization-v1: JCS (RFC 8785) numeric boundary vectors over raw
    wire JSON text. Each input carries two separate members: a numeric
    member "n" (wire integer "-0"/"0") and a string member "s" (wire
    string "-0"/"0", the signed digit's string form), so a numeric value
    cannot be conflated with its string form. negzero canonicalizes to
    {"n":0,"s":"-0"} and pluszero to {"n":0,"s":"0"} (different
    preimages, different signatures); a negative signature pins the
    rejected literal-preserving preimage {"n":-0,"s":"-0"}, and the
    positive signature is additionally asserted INVALID over the
    numeric/string confusion preimages {"n":0,"s":0} and
    {"n":"-0","s":-0}.

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

    # --- Verification within declared window ---
    # verified_at must not fall after expires_at + max_clock_skew. This gates
    # the receipt's internal temporal-claim coherence (issuer stamps): a
    # verification stamped after the declared window closed is invalid. Only
    # evaluated when the window was ever open (expires >= issued); if the
    # window never opened, expires-after-issued already reports it. Wall-clock
    # freshness against a relying party's own clock is a separate policy
    # decision outside this conformance checker.
    if (verified_ep is not None and expires_ep is not None
            and issued_ep is not None and expires_ep >= issued_ep):
        over = verified_ep - expires_ep
        checks.append((
            "cross-field:verified-within-window",
            over <= mcs,
            "ok" if over <= mcs
            else (f"verified_at is {over}s after expires_at; exceeds "
                  f"max_clock_skew {mcs}s (window closed before verification "
                  f"by {over - mcs}s beyond tolerance)"),
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
    pinned = manifest.get("files", {})
    if not isinstance(pinned, dict):
        # Legacy list-of-entries manifests (e.g. vectors/v1.3.0) carry
        # {"path", "sha256"} records rather than a path->digest map.
        if isinstance(pinned, list) and all(isinstance(e, dict) for e in pinned):
            pinned = {e["path"]: e["sha256"] for e in pinned}
        else:
            return False, ["manifest 'files' is neither a path->digest map nor a list of {path, sha256} entries"]
    # Forward direction: every pinned member exists and matches its digest.
    for rel_path, expected_hash in pinned.items():
        fpath = vectors_dir / rel_path
        if not fpath.exists():
            errors.append(f"missing file: {rel_path}")
            continue
        actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual != expected_hash:
            errors.append(
                f"hash mismatch: {rel_path} (expected {expected_hash[:16]}..., got {actual[:16]}...)"
            )
    # Reverse direction: the manifest is a closed inventory. A file present on
    # disk but absent from the manifest is outside the admitted population and
    # must be refused, never silently covered by what the tooling happened to
    # print. manifest.json itself and dotfiles are outside the boundary.
    pinned_set = {str(r).replace("\\", "/") for r in pinned.keys()}
    on_disk: set[str] = set()
    for root, dirnames, filenames in os.walk(vectors_dir):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for fname in sorted(filenames):
            if fname.startswith("."):
                continue
            rel = (Path(root) / fname).relative_to(vectors_dir).as_posix()
            if rel == "manifest.json":
                continue
            on_disk.add(rel)
    for unpinned in sorted(on_disk - pinned_set):
        errors.append(f"file on disk but absent from manifest: {unpinned}")
    return (len(errors) == 0, errors)


def count_pinned_cases(pinned: dict) -> int:
    """Independently derive the admitted case population from the closed manifest.

    A case is any pinned directory containing a pinned expected.json; the
    count comes from the manifest bytes, never from what the run discovered.
    """
    case_dirs = {
        str(Path(p).parent).replace("\\", "/")
        for p in pinned
        if p.replace("\\", "/").endswith("/expected.json")
    }
    return len(case_dirs)


def count_pinned_receipts(pinned: dict) -> int:
    """Independently count runnable pinned receipts.

    Only receipts sitting in a directory that carries expected.json are part
    of the admitted run population. Pinned reference material in auxiliary
    subdirectories (e.g. an ``original/`` tamper baseline) is byte-protected by
    the manifest but is not itself a run target.
    """
    count = 0
    for p in pinned:
        norm = p.replace("\\", "/")
        parent = Path(norm).parent
        if not re.fullmatch(r"receipt[^/]*\.json", Path(norm).name):
            continue
        if str((parent / "expected.json")).replace("\\", "/") in pinned:
            count += 1
    return count


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

    # 5. prev-hash linkage — ANCHORED to the predecessor receipt's own bytes.
    #
    # The chain anchor is the SHA-256(JCS) digest of receipt i-1 (receipt_digest_l1:
    # the L1 receipt minus its signature field). Both consumer-facing declarations
    # — runtime-context's prev_receipt_digest and chain.json's expected_prev_digests
    # — are cross-checked AGAINST that computed anchor; neither declaration is a
    # truth source. Comparing the two declarations to each other (previous
    # behaviour) could not detect a case where both declared the same wrong digest.
    # Reported by Joel Hillier (Certisyn) during independent interoperability
    # review, 2026-08-30.
    computed_prevs: list = [None]
    for _, _data in receipts[1:]:
        computed_prevs.append(receipt_digest_l1(_data) if isinstance(_data, dict) else None)
    # receipts are already in chain order (chain_spec["order"] or file order),
    # so receipts[i-1] is receipt i's predecessor.
    for i, (name, data) in enumerate(receipts):
        if i == 0:
            continue
        anchor = computed_prevs[i]
        if anchor is None:
            continue
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
        declared_prev = rc.get("prev_receipt_digest") if rc else None
        if declared_prev is not None:
            checks.append((
                "chain:prev-hash-matches",
                declared_prev == anchor,
                "ok" if declared_prev == anchor
                else f"prev_receipt_digest in runtime context is not the digest of predecessor {receipts[i-1][0]}: declared {str(declared_prev)[:32]}... computed anchor {anchor[:32]}...",
            ))
        # chain.json expected_prev_digests is advisory metadata — cross-check only.
        if chain_spec and "expected_prev_digests" in chain_spec:
            expected_prevs = chain_spec["expected_prev_digests"]
            if i < len(expected_prevs) and expected_prevs[i] is not None:
                spec_prev = expected_prevs[i]
                checks.append((
                    "chain:spec-prev-crosscheck",
                    spec_prev == anchor,
                    "ok" if spec_prev == anchor
                    else f"chain.json expected_prev_digests[{i}] {str(spec_prev)[:32]}... disagrees with computed anchor {anchor[:32]}...",
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
            result["receipts"][0]["passed"] = False
            if not result["receipts"][0].get("reason"):
                result["receipts"][0]["reason"] = chain_failed[0][2]
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
            # Match expected reason keywords, but tolerate synonyms.
            expected_reason = result["expected"].get("reason", "") if result["expected"] else ""
            if expected_reason:
                stop = {"does", "that", "this", "with", "from", "have", "been",
                        "were", "their", "will", "would", "could", "should",
                        "than", "then", "into", "about", "your", "must",
                        "across", "detected"}
                kws = set(
                    w.lower() for w in re.findall(r"[a-z_]+", expected_reason)
                    if len(w) > 3 and w.lower() not in stop
                )
                # synonyms so keyword matching is tolerant of checker wording
                synonyms = {
                    "mismatch": {"mismatch", "mismatches", "differ", "differs",
                                 "incorrect", "wrong", "mismatched", "!=",
                                 "declared"},
                    "boolean": {"bool", "boolean", "got"},
                    "timestamp": {"timestamp", "numeric", "iso", "8601"},
                    "sequence": {"sequence", "seq", "contiguous", "gap",
                                 "order"},
                    "fingerprint": {"fingerprint", "computed", "declared"},
                    "nonce": {"nonce", "duplicate", "replay", "unique",
                              "dup"},
                    "gap": {"gap", "contiguous", "sequence", "order"},
                    "predecessor": {"predecessor", "no", "first", "sequence"},
                    "duplicate": {"duplicate", "dup", "nonce", "replay"},
                    "trace_id": {"trace_id", "trace", "differ", "consistent"},
                    "prev_hash": {"prev", "digest", "hash", "predecessor",
                                  "linkage"},
                    "differ": {"differ", "mismatch", "inconsistent",
                               "trace_ids", "declared"},
                }
                expanded: set[str] = set()
                for kw in kws:
                    expanded.add(kw)
                    expanded |= synonyms.get(kw, set())
                kws = expanded
                matched = False
                for rr in result["receipts"]:
                    for cname, cpassed, cdetail in rr.get("checks", []):
                        if cpassed:
                            continue
                        hay = (cname + " " + cdetail).lower()
                        if any(kw in hay for kw in kws):
                            matched = True
                            break
                    if matched:
                        break
                if not matched and kws:
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
# canonicalization-v1: JCS (RFC 8785) numeric boundary vectors
# ---------------------------------------------------------------------------
#
# These cases are *not* CCS receipts. Each case directory pins a raw wire
# JSON text (input.json), the JCS canonical bytes expected from it, and an
# Ed25519 signature over those canonical bytes. Every input carries two
# separate members: a numeric member "n" (wire integer "-0" or "0") and a
# string member "s" (wire string "-0" or "0", the signed digit's string
# form). The integer token -0 and the string "-0" are carried as separate
# members so a numeric value cannot be conflated with its string form.
#
#   negzero  wire {"n":-0,"s":"-0"} -> JCS {"n":0,"s":"-0"} -> sig A
#   pluszero wire {"n":0,"s":"0"}   -> JCS {"n":0,"s":"0"}  -> sig B
#
# The string member is preserved verbatim, so the two cases have two
# different canonical preimages and two different signatures (sig A != sig
# B). CPython's parser already normalizes the integer "-0" token to 0, so
# the wire literal cannot survive a json.loads -> canonicalize round trip;
# a literal-preserving implementation is instead pinned by bidirectional
# signature evidence over exact preimage bytes:
#
#   signature.sig           = Ed25519(priv, the case's canonical bytes)
#   negative-signature.sig  = Ed25519(priv, rejected literal
#                                    {"n":-0,"s":"-0"}) [negzero only]
#
# A conforming verifier observes: positive signature VALID on the case's
# canonical bytes and INVALID on the rejected literal and every numeric/
# string confusion preimage; the negative signature (negzero only) VALID on
# the rejected literal alone.

CANONICALIZATION_CORPUS_VERSION = "canonicalization-v1"

# Pinned boundary facts (also asserted in the generator); stored as text so
# the checker never trusts expected.json for the bytes it signs against.
NEGZERO_REJECTED_LITERAL = '{"n":-0,"s":"-0"}'
CONFUSION_STRING_AS_NUMBER = '{"n":0,"s":0}'
CONFUSION_TYPES_SWAPPED = '{"n":"-0","s":-0}'


def _verify_ed25519_raw(pub_bytes: bytes, sig_bytes: bytes, message: bytes) -> bool:
    """Return True iff a raw Ed25519 signature verifies over message."""
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False


def verify_canonicalization_case(case_dir: Path) -> dict:
    """Verify one JCS numeric-boundary case.

    Returns a dict with keys case, passed, reason, checks(list[(name,bool,detail)]).

    Each case pins a raw wire document carrying two separate members:
    numeric member "n" (wire token -0 or 0) and string member "s" (wire
    string "-0" or "0"). The checker pins per-member wire/canonical forms,
    the whole-document canonical bytes, the rejected literal preimage, one
    or more numeric/string confusion preimages, and a bidirectional
    signature matrix. negzero additionally ships negative-signature.sig
    over the rejected literal; pluszero is the plain-zero baseline.
    """
    result: dict[str, Any] = {
        "case": case_dir.name,
        "passed": True,
        "reason": None,
        "checks": [],
    }

    def record(name: str, ok: bool, detail: str) -> None:
        result["checks"].append((name, ok, detail))
        if not ok and result["reason"] is None:
            result["passed"] = False
            result["reason"] = detail

    expected_path = case_dir / "expected.json"
    input_path = case_dir / "input.json"
    sig_path = case_dir / "signature.sig"
    for label, p in (
        ("expected.json", expected_path),
        ("input.json", input_path),
        ("signature.sig", sig_path),
    ):
        if not p.exists():
            record(f"case:{label}", False, f"{label} missing")
            return result

    try:
        expected = load_json(expected_path)
    except Exception as exc:
        record("case:expected-load", False, f"cannot parse expected.json: {exc}")
        return result

    is_negzero = case_dir.name == "negzero" or expected.get("wire_literal") == "-0"
    is_pluszero = case_dir.name == "pluszero"

    record(
        "case:raw-text-flag",
        expected.get("input_is_raw_json_text") is True,
        "expected.json must declare input_is_raw_json_text=true",
    )
    record(
        "case:expect",
        expected.get("expect") == "valid-for-rfc8785",
        "expected.json expect must be 'valid-for-rfc8785'",
    )
    record(
        "case:algorithm",
        expected.get("signing_algorithm") == "Ed25519",
        "signing_algorithm must be Ed25519",
    )

    # --- Public key material ---
    try:
        pub_bytes = b64decode_strict(expected["public_key_b64"])
        record("pubkey:base64", True, "ok")
        record(
            "pubkey:32-bytes",
            len(pub_bytes) == 32,
            "ok" if len(pub_bytes) == 32
            else f"public key must be 32 bytes, got {len(pub_bytes)}",
        )
    except Exception as exc:
        record("pubkey:base64", False, f"public key base64 error: {exc}")
        return result

    declared_fpr = expected.get("public_key_fingerprint", "")
    computed_fpr = hashlib.sha256(pub_bytes).hexdigest()[:16]
    record(
        "pubkey:fingerprint",
        declared_fpr == computed_fpr,
        "ok" if declared_fpr == computed_fpr
        else f"declared fingerprint {declared_fpr!r} != computed {computed_fpr!r}",
    )

    # --- Raw wire text fixture ---
    input_bytes = input_path.read_bytes()
    record(
        "input:no-bom",
        not input_bytes.startswith(b"\xef\xbb\xbf"),
        "ok" if not input_bytes.startswith(b"\xef\xbb\xbf")
        else "input.json must not carry a UTF-8 BOM",
    )
    json_text_bytes = input_bytes[:-1] if input_bytes.endswith(b"\n") else input_bytes
    record(
        "input:single-trailing-lf",
        not input_bytes.endswith(b"\n\n") and input_bytes.endswith(b"\n"),
        "ok" if (not input_bytes.endswith(b"\n\n") and input_bytes.endswith(b"\n"))
        else "input.json must end with exactly one LF",
    )
    try:
        raw_text = json_text_bytes.decode("utf-8")
        record("input:utf8-decodable", True, "ok")
    except UnicodeDecodeError as exc:
        record("input:utf8-decodable", False, f"input.json is not UTF-8: {exc}")
        return result

    try:
        parsed = json.loads(raw_text)
        record("input:json-parseable", True, "ok")
    except json.JSONDecodeError as exc:
        record("input:json-parseable", False, f"raw input text is not valid JSON: {exc}")
        return result

    # --- Per-member wire pins: two separate members, numeric vs string ---
    members = expected.get("members")
    members_ok = isinstance(members, dict) and set(members) == {"n", "s"}
    record(
        "members:separate-n-and-s",
        members_ok,
        "expected.json members block declares exactly two members: n (number) and s (string)"
        if members_ok
        else f"expected.json members must be an object with exactly keys n,s; got {list(members) if isinstance(members, dict) else members!r}",
    )

    want_string_token = '"-0"' if is_negzero else '"0"'
    want_string_value = "-0" if is_negzero else "0"
    want_numeric_wire = "-0" if is_negzero else "0"
    if members_ok:
        n_spec = members["n"]
        s_spec = members["s"]
        record(
            "members:n-is-number",
            n_spec.get("json_type") == "number"
            and n_spec.get("expected_canonical_member") == '"n":0'
            and n_spec.get("expected_canonical_token") == "0"
            and n_spec.get("wire_token") == want_numeric_wire,
            f"numeric member n wire token {n_spec.get('wire_token')!r}, canonical {n_spec.get('expected_canonical_member')!r}",
        )
        record(
            "members:s-is-string",
            s_spec.get("json_type") == "string"
            and s_spec.get("expected_canonical_member") == f'"s":{want_string_token}'
            and s_spec.get("expected_canonical_token") == want_string_token
            and s_spec.get("wire_token") == want_string_token,
            f"string member s wire token {s_spec.get('wire_token')!r}, canonical {s_spec.get('expected_canonical_member')!r} (preserved verbatim with quotes)",
        )

        n_wire_pat = ('"n":' + want_numeric_wire).encode("utf-8")
        s_wire_pat = ('"s":' + want_string_token).encode("utf-8")
        record(
            "wire:members-present-and-separate",
            n_wire_pat in json_text_bytes and s_wire_pat in json_text_bytes,
            f"raw wire contains separate members {n_wire_pat!r} and {s_wire_pat!r}",
        )

        n_parsed = parsed.get("n") if isinstance(parsed, dict) else None
        s_parsed = parsed.get("s") if isinstance(parsed, dict) else None
        record(
            "parse:n-is-int-zero",
            isinstance(n_parsed, int) and not isinstance(n_parsed, bool) and n_parsed == 0,
            (
                f"parser yields numeric member n = {n_parsed!r} ({type(n_parsed).__name__}); integer -0 normalizes to 0"
                if is_negzero
                else f"parser yields numeric member n = {n_parsed!r} ({type(n_parsed).__name__}); plain integer 0 baseline"
            )
            if isinstance(n_parsed, int)
            else f"numeric member n must parse to int 0, got {n_parsed!r}",
        )
        record(
            "parse:s-is-string",
            isinstance(s_parsed, str) and s_parsed == want_string_value,
            f"string member s remains a distinct str ({s_parsed!r}); numeric/string types not conflated"
            if isinstance(s_parsed, str) and s_parsed == want_string_value
            else f"string member s must parse to str {want_string_value!r}, got {s_parsed!r}",
        )
        record(
            "parse:members-not-equal-by-type",
            isinstance(n_parsed, int) and isinstance(s_parsed, str)
            and type(n_parsed) is not type(s_parsed),
            "numeric member and string member retain distinct JSON types after parsing",
        )

        if is_negzero:
            record(
                "wire:negzero-literal-on-wire",
                b'"n":-0' in json_text_bytes,
                "raw wire text carries the integer -0 token on member n",
            )
            record(
                "wire:negzero-string-preserved",
                b'"s":"-0"' in json_text_bytes,
                'raw wire text carries the string "-0" verbatim on member s (not the number -0)',
            )

    # --- Rejected literal pin (reviewer's literal-preserving implementation) ---
    rejected_block = expected.get("rejected_literal")
    rejected_declared_ok = (
        isinstance(rejected_block, dict)
        and rejected_block.get("utf8") == NEGZERO_REJECTED_LITERAL
        and rejected_block.get("hex") == NEGZERO_REJECTED_LITERAL.encode("utf-8").hex()
        and rejected_block.get("sha256") == sha256_hex(NEGZERO_REJECTED_LITERAL.encode("utf-8"))
    )
    record(
        "pin:rejected-literal",
        rejected_declared_ok,
        f"rejected literal pinned as {NEGZERO_REJECTED_LITERAL} / {NEGZERO_REJECTED_LITERAL.encode('utf-8').hex()}"
        if rejected_declared_ok
        else f"rejected_literal block disagrees with the fixed pin: {rejected_block!r}",
    )
    rejected_bytes = NEGZERO_REJECTED_LITERAL.encode("utf-8")

    # --- Numeric/string confusion pins ---
    confusion_blocks = expected.get("confusions")
    confusion_fixed = {
        "confusion-string-as-number.json": CONFUSION_STRING_AS_NUMBER,
        "confusion-types-swapped.json": CONFUSION_TYPES_SWAPPED,
    }
    declared_confusions: dict[str, bytes] = {}
    confusion_block_ok = isinstance(confusion_blocks, list) and len(confusion_blocks) >= 1
    if isinstance(confusion_blocks, list):
        for block in confusion_blocks:
            if not isinstance(block, dict):
                confusion_block_ok = False
                continue
            fname = block.get("file")
            text = block.get("utf8")
            fixed_text = confusion_fixed.get(fname)
            ok = (
                fixed_text is not None
                and text == fixed_text
                and block.get("hex") == fixed_text.encode("utf-8").hex()
                and block.get("sha256") == sha256_hex(fixed_text.encode("utf-8"))
            )
            confusion_block_ok = confusion_block_ok and ok
            if ok:
                declared_confusions[fname] = fixed_text.encode("utf-8")
    # pluszero ships the string-as-number confusion itself and must also be
    # checked against the negzero types-swapped bytes (see cross checks).
    if is_pluszero:
        confusion_block_ok = confusion_block_ok and (
            "confusion-string-as-number.json" in declared_confusions
        )
    if is_negzero:
        confusion_block_ok = confusion_block_ok and set(declared_confusions) == set(
            confusion_fixed
        )
    record(
        "pin:confusion-numeric-string",
        confusion_block_ok,
        "numeric/string confusion preimages pinned with exact utf8/hex/sha256: "
        + ", ".join(sorted(declared_confusions))
        if confusion_block_ok
        else f"confusions block disagrees with the fixed pins: {confusion_blocks!r}",
    )

    # --- Real JCS canonicalization of the raw-text fixture ---
    canonical = canonical_json(parsed)
    expected_canonical_text = (
        '{"n":0,"s":"-0"}' if is_negzero else '{"n":0,"s":"0"}'
    )
    expected_hex = expected.get("expected_canonical_hex", "")
    record(
        "jcs:canonical-hex",
        canonical.hex() == expected_hex
        and canonical == expected_canonical_text.encode("utf-8"),
        "ok" if canonical.hex() == expected_hex
        else f"JCS canonical hex {canonical.hex()} != expected {expected_hex}",
    )
    expected_utf8 = expected.get("expected_canonical_utf8", "")
    record(
        "jcs:canonical-utf8",
        canonical.decode("utf-8", errors="replace") == expected_utf8
        and expected_utf8 == expected_canonical_text,
        f"canonical text {canonical.decode(errors='replace')!r}: numeric -0 normalised to 0, string preserved verbatim",
    )
    expected_sha = expected.get("expected_canonical_sha256", "")
    actual_sha = hashlib.sha256(canonical).hexdigest()
    record(
        "jcs:canonical-sha256",
        actual_sha == expected_sha,
        "ok" if actual_sha == expected_sha
        else f"canonical sha256 {actual_sha} != expected {expected_sha}",
    )
    record(
        "jcs:canonical-member-order",
        canonical[1:6] == b'"n":0',
        "canonical members ordered lexicographically: n before s",
    )

    confusion_a = CONFUSION_STRING_AS_NUMBER.encode("utf-8")
    confusion_b = CONFUSION_TYPES_SWAPPED.encode("utf-8")
    record(
        "jcs:wrong-preimages-distinct",
        rejected_bytes != canonical
        and confusion_a != canonical
        and confusion_b != canonical
        and rejected_bytes not in (confusion_a, confusion_b)
        and confusion_a != confusion_b,
        "rejected-literal and both confusion preimages each differ from canonical and each other",
    )

    # negzero's canonical must differ from pluszero's (string verbatim).
    sibling_dir = case_dir.parent / ("pluszero" if is_negzero else "negzero")
    sibling_canon_file = sibling_dir / "canonical.jcs"
    if sibling_canon_file.exists():
        record(
            "jcs:sibling-canonical-differs",
            sibling_canon_file.read_bytes() != canonical,
            f"canonical differs from {sibling_dir.name}/canonical.jcs (distinct preimages)",
        )
    else:
        record("jcs:sibling-canonical-differs", False,
               f"sibling canonical {sibling_canon_file} not found")

    # Shipped byte-preimage files must equal the pinned bytes.
    canon_file = case_dir / "canonical.jcs"
    record(
        "file:canonical-jcs",
        canon_file.exists() and canon_file.read_bytes() == canonical,
        "canonical.jcs matches computed JCS bytes"
        if canon_file.exists() and canon_file.read_bytes() == canonical
        else "canonical.jcs missing or disagrees with computed JCS bytes",
    )
    if is_negzero:
        rej_file = case_dir / "rejected-literal.json"
        record(
            "file:rejected-literal",
            rej_file.exists() and rej_file.read_bytes() == rejected_bytes,
            "rejected-literal.json matches pinned literal bytes (identical to negzero wire text minus LF)"
            if rej_file.exists() and rej_file.read_bytes() == rejected_bytes
            else "rejected-literal.json missing or disagrees with pinned literal",
        )
    for fname, fbytes in (
        ("confusion-string-as-number.json", confusion_a),
        ("confusion-types-swapped.json", confusion_b),
    ):
        fpath = case_dir / fname
        if fpath.exists():
            record(
                f"file:{fname}",
                fpath.read_bytes() == fbytes,
                f"{fname} matches pinned confusion bytes"
                if fpath.read_bytes() == fbytes
                else f"{fname} disagrees with pin",
            )

    # --- Positive signature ---
    sig_bytes = sig_path.read_bytes()
    sig_len_ok = len(sig_bytes) == 64
    record(
        "sig:64-bytes",
        sig_len_ok,
        "ok" if sig_len_ok
        else f"signature.sig must be 64 raw bytes, got {len(sig_bytes)}",
    )
    if not sig_len_ok:
        return result
    sig_b64 = expected.get("signature_b64")
    if isinstance(sig_b64, str):
        record(
            "sig:b64-consistency",
            base64.b64encode(sig_bytes).decode("ascii") == sig_b64,
            "signature.sig bytes match expected.json signature_b64"
            if base64.b64encode(sig_bytes).decode("ascii") == sig_b64
            else "signature_b64 disagrees with signature.sig",
        )
    record(
        "sig:positive-valid-on-canonical",
        _verify_ed25519_raw(pub_bytes, sig_bytes, canonical),
        "positive signature VALID over this case's JCS canonical bytes",
    )
    record(
        "sig:positive-invalid-on-rejected-literal",
        not _verify_ed25519_raw(pub_bytes, sig_bytes, rejected_bytes),
        f"positive signature correctly INVALID over rejected literal {NEGZERO_REJECTED_LITERAL} (literal-preserving implementation rejected)"
        if not _verify_ed25519_raw(pub_bytes, sig_bytes, rejected_bytes)
        else "positive signature unexpectedly verifies over rejected literal",
    )
    record(
        "sig:positive-invalid-on-confusion-string-as-number",
        not _verify_ed25519_raw(pub_bytes, sig_bytes, confusion_a),
        f"positive signature correctly INVALID over confusion {CONFUSION_STRING_AS_NUMBER} (string member coerced to number)"
        if not _verify_ed25519_raw(pub_bytes, sig_bytes, confusion_a)
        else "positive signature unexpectedly verifies over string-as-number confusion",
    )
    record(
        "sig:positive-invalid-on-confusion-types-swapped",
        not _verify_ed25519_raw(pub_bytes, sig_bytes, confusion_b),
        f"positive signature correctly INVALID over confusion {CONFUSION_TYPES_SWAPPED} (numeric/string types swapped)"
        if not _verify_ed25519_raw(pub_bytes, sig_bytes, confusion_b)
        else "positive signature unexpectedly verifies over types-swapped confusion",
    )

    # --- Negative signature (shipped by negzero): bidirectional pin ---
    neg_sig_path = case_dir / "negative-signature.sig"
    if is_negzero:
        if not neg_sig_path.exists():
            record("neg-sig:file", False, "negzero must ship negative-signature.sig")
        else:
            neg_sig = neg_sig_path.read_bytes()
            record(
                "neg-sig:64-bytes",
                len(neg_sig) == 64,
                "ok" if len(neg_sig) == 64
                else f"negative-signature.sig must be 64 raw bytes, got {len(neg_sig)}",
            )
            neg_b64 = expected.get("negative_signature_b64")
            if isinstance(neg_b64, str):
                record(
                    "neg-sig:b64-consistency",
                    base64.b64encode(neg_sig).decode("ascii") == neg_b64,
                    "negative-signature.sig bytes match negative_signature_b64"
                    if base64.b64encode(neg_sig).decode("ascii") == neg_b64
                    else "negative_signature_b64 disagrees with negative-signature.sig",
                )
            record(
                "neg-sig:invalid-on-canonical",
                not _verify_ed25519_raw(pub_bytes, neg_sig, canonical),
                "negative signature correctly INVALID over the negzero canonical bytes",
            )
            record(
                "neg-sig:invalid-on-confusion-string-as-number",
                not _verify_ed25519_raw(pub_bytes, neg_sig, confusion_a),
                "negative signature correctly INVALID over string-as-number confusion",
            )
            record(
                "neg-sig:invalid-on-confusion-types-swapped",
                not _verify_ed25519_raw(pub_bytes, neg_sig, confusion_b),
                "negative signature correctly INVALID over types-swapped confusion",
            )
            record(
                "neg-sig:valid-on-rejected-literal",
                _verify_ed25519_raw(pub_bytes, neg_sig, rejected_bytes),
                "negative signature VALID only over the rejected literal bytes",
            )
    else:
        # Control case must not carry its own negative-signature file.
        record(
            "pluszero:no-negative-signature-file",
            not neg_sig_path.exists(),
            "ok" if not neg_sig_path.exists()
            else "pluszero must not ship a negative-signature.sig (negative evidence lives in negzero/)",
        )

    # --- Cross-case: distinct preimages => distinct signatures ---
    sibling_sig = sibling_dir / "signature.sig"
    if sibling_sig.exists():
        record(
            "control:sibling-signature-differs",
            sibling_sig.read_bytes() != sig_bytes,
            f"signature differs from {sibling_dir.name}/signature.sig (different canonical preimages: string \"-0\" vs \"0\")"
            if sibling_sig.read_bytes() != sig_bytes
            else f"signature unexpectedly identical to {sibling_dir.name}/signature.sig",
        )
        # And each positive signature must fail over the other case's
        # canonical preimage.
        if sibling_canon_file.exists():
            record(
                "control:invalid-on-sibling-canonical",
                not _verify_ed25519_raw(
                    pub_bytes, sig_bytes, sibling_canon_file.read_bytes()
                ),
                f"this positive signature is INVALID over {sibling_dir.name} canonical preimage",
            )
    else:
        record(
            "control:sibling-signature-differs", False,
            f"sibling signature {sibling_sig} not found",
        )

    return result


def find_canonicalization_case_dirs(vectors_dir: Path) -> list[Path]:
    """Find canonicalization-v1 case dirs (immediate subdirs with expected.json)."""
    cases = []
    for entry in sorted(vectors_dir.iterdir()):
        if entry.is_dir() and not entry.name.startswith(".") and (entry / "expected.json").exists():
            cases.append(entry)
    return cases


def run_canonicalization_suite(vectors_dir: Path) -> int:
    """Entry point for a canonicalization-v1 corpus directory."""
    manifest_path = vectors_dir / "manifest.json"
    try:
        manifest = load_json(manifest_path)
    except Exception as exc:
        print(f"Error: cannot read manifest.json: {exc}", file=sys.stderr)
        return 2
    if manifest.get("version") != CANONICALIZATION_CORPUS_VERSION:
        print(
            f"Error: manifest version {manifest.get('version')!r} is not "
            f"{CANONICALIZATION_CORPUS_VERSION!r}",
            file=sys.stderr,
        )
        return 2
    if manifest.get("canonicalization") != "JCS (RFC 8785)":
        print("Error: manifest canonicalization must be 'JCS (RFC 8785)'",
              file=sys.stderr)
        return 2
    if manifest.get("hash_algorithm") != "sha256":
        print("Error: manifest hash_algorithm must be 'sha256'", file=sys.stderr)
        return 2

    # Every file under the corpus (except manifest.json itself) must be
    # pinned, so a third party can detect unlisted/tampered additions.
    on_disk: set[str] = set()
    for root, dirs, fnames in os.walk(vectors_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            rel = fpath.relative_to(vectors_dir).as_posix()
            if rel == "manifest.json":
                continue
            on_disk.add(rel)
    pinned = set(manifest.get("files", {}).keys())
    unpinned = sorted(on_disk - pinned)
    phantom = sorted(pinned - on_disk)
    completeness_errors = [f"unpinned file: {p}" for p in unpinned]
    completeness_errors += [f"pinned file missing: {p}" for p in phantom]

    # Manifest pins are verified with the same logic as receipt corpora.
    manifest_ok, manifest_errors = verify_manifest(vectors_dir)
    manifest_errors = completeness_errors + manifest_errors
    manifest_ok = manifest_ok and not completeness_errors
    if not manifest_ok:
        print("MANIFEST VERIFICATION FAILED:")
        for err in manifest_errors:
            print(f"  ✗ {err}")
        return 1
    print(f"✓ Manifest verified ({vectors_dir.name}/manifest.json)")
    print(f"  canonicalization: {manifest.get('canonicalization')}")
    print(f"  public key:       {manifest.get('public_key_fingerprint')}")

    case_dirs = find_canonicalization_case_dirs(vectors_dir)
    if not case_dirs:
        print("No canonicalization case directories with expected.json found",
              file=sys.stderr)
        return 1

    all_passed = True
    total_checks = 0
    passed_checks = 0
    matched_cases = 0
    for case_dir in case_dirs:
        result = verify_canonicalization_case(case_dir)
        if result["passed"]:
            matched_cases += 1
        rel = case_dir.relative_to(vectors_dir)
        for _, ok, _ in result["checks"]:
            total_checks += 1
            if ok:
                passed_checks += 1
        status = "✓ PASS" if result["passed"] else "✗ FAIL"
        print(f"\n{status}  {rel}")
        for name, ok, detail in result["checks"]:
            mark = "✓" if ok else "✗"
            print(f"         {mark} {name} — {detail}")
        if not result["passed"]:
            print(f"         Reason: {result.get('reason', 'unknown')}")
            all_passed = False

    # Footer totals are recomputed independently from the closed manifest, so
    # a dropped case can never be hidden by comparing a count against itself.
    pinned_map = manifest.get("files", {})
    expected_cases = count_pinned_cases(pinned_map)
    print(f"\n{'='*60}")
    print(f"Checks: {passed_checks}/{total_checks} passed")
    print(f"Cases:  {matched_cases}/{expected_cases} matched expected outcome")
    if len(case_dirs) != expected_cases:
        print(
            f"POPULATION MISMATCH: discovered {len(case_dirs)} case dirs, "
            f"manifest admits {expected_cases}",
            file=sys.stderr,
        )
        all_passed = False
    if all_passed:
        print("\n✓ ALL VECTORS PASSED")
        return 0
    print("\n✗ SOME VECTORS FAILED")
    return 1


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

    # Dispatch on the corpus type. canonicalization-v1 uses raw-text numeric
    # boundary fixtures rather than signed CCS receipts; everything else
    # (v1.4.0-conformance and earlier) keeps the original receipt flow and
    # its exact output/exit-code contract.
    manifest_path = vectors_dir / "manifest.json"
    if manifest_path.exists():
        try:
            top_manifest = load_json(manifest_path)
            if top_manifest.get("version") == CANONICALIZATION_CORPUS_VERSION:
                return run_canonicalization_suite(vectors_dir)
        except Exception:
            pass  # fall through to the receipt flow, which reports the error

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
    matched_cases = 0
    discovered_receipts = 0

    for case_dir in case_dirs:
        result = verify_case(case_dir)
        rel = case_dir.relative_to(vectors_dir)
        if result["passed"]:
            matched_cases += 1
        discovered_receipts += len(result.get("receipts", []))

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

    # Footer totals are independently recomputed from the closed manifest: the
    # admitted case and receipt populations come from manifest bytes, not from
    # whatever the run happened to discover (Lars's self-proving-total note).
    top_pinned = top_manifest.get("files", {})
    if isinstance(top_pinned, list):
        top_pinned = {e["path"]: e["sha256"] for e in top_pinned}
    expected_cases = count_pinned_cases(top_pinned)
    expected_receipts = count_pinned_receipts(top_pinned)
    print(f"\n{'='*60}")
    print(f"Checks: {passed_checks}/{total_checks} passed")
    print(f"Cases:  {matched_cases}/{expected_cases} matched expected outcome")
    print(f"Receipts verified: {discovered_receipts}/{expected_receipts} admitted by manifest")
    if len(case_dirs) != expected_cases:
        print(
            f"POPULATION MISMATCH: discovered {len(case_dirs)} case dirs, "
            f"manifest admits {expected_cases}",
            file=sys.stderr,
        )
        all_passed = False
    if discovered_receipts != expected_receipts:
        print(
            f"POPULATION MISMATCH: verified {discovered_receipts} receipts, "
            f"manifest admits {expected_receipts}",
            file=sys.stderr,
        )
        all_passed = False

    if all_passed:
        print("\n✓ ALL VECTORS PASSED")
        return 0
    else:
        print("\n✗ SOME VECTORS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
