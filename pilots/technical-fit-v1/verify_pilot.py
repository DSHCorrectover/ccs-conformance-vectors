#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""IICP x CCS pilot — offline batch verifier (CC0).

2026-11-07 full rewrite closing the gaps found by external review
(R. La Touche pre-send review, 2026-11-06):

  v1 gap 1 — single-payload signature check only. This version adds:
    * closed-inventory manifest validation (both directions: every file
      pinned with matching SHA-256, no unpinned fixture files present);
    * canonical-bytes recompute: signatures are verified over JCS bytes
      recomputed from the source JSON, and the pinned ``canonical_hex``
      must match the recomputation (detects canonicalizer divergence);
    * verdict-vs-contract check: C1-C4 and C6 MUST verify valid, C5 MUST
      fail — a batch where C5 "passes" is itself a failure;
    * cross-submission duplicate detection: any two receipts whose
      canonical payloads are identical (C6 is a canonical-payload-
      identical copy of C1 by design) are reported as replay/duplicate
      candidates for the correlation layer;
    * footer totals recomputed from the manifest, not from the scan
      itself (self-proving-total protection, same rule as
      independent_checker.py since c848fae).

  v1 gap 2 — canonicalization was ``json.dumps(sort_keys=True)``, which is
  NOT RFC 8785 (JCS): number formatting differs (``-0.0``, ``1e+21``,
  ``0.000001``), and key ordering follows code points instead of UTF-16
  code units. This version implements RFC 8785 serialization (ES6
  Number::toString + UTF-16BE key ordering) with no new dependencies and
  rejects non-finite numbers (JCS forbids NaN/Infinity).

  v1 gap 3 — output depended on interpreter hash seed. All iteration here
  is ordered; output is byte-identical across PYTHONHASHSEED values.

Usage:
    python verify_pilot.py                                  # batch mode (all fixtures + manifest)
    python verify_pilot.py fixtures/case-C1-receipt.json    # single receipt (legacy behaviour)

Exit codes: 0 = all checks passed; 1 = verification failure; 2 = usage/IO error.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
PUB_PATH = HERE / "pilot-public-key.pub.pem"

# ---------------------------------------------------------------------------
# RFC 8785 (JCS) canonicalization — no third-party dependency
# ---------------------------------------------------------------------------

_ES6_SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def _es6_number_to_string(value) -> str:
    """ECMA-262 Number::toString(x, 10) for JSON numbers (RFC 8785 §3.2.2.3)."""
    if isinstance(value, bool):  # bool must be handled by the caller (JSON true/false)
        raise TypeError("bool is not a JSON number")
    if isinstance(value, int):
        return str(value)
    x = float(value)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("non-finite number is not allowed in JCS")
    if x == 0.0:
        return "0"  # +0 and -0 both serialize to "0"
    sign = "-" if x < 0 else ""
    x = -x if x < 0 else x  # work on the absolute value; sign reattached below
    # Shortest round-trip digits via repr, then reformat per ES6 thresholds.
    r = repr(x)
    if "e" in r or "E" in r:
        mant, _, exp_s = r.replace("E", "e").partition("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    all_digits = ip + fp
    stripped = all_digits.lstrip("0")
    lead = len(all_digits) - len(stripped)
    s = stripped.rstrip("0") or "0"
    k = len(s)  # number of significant digits (ES6 'k')
    # decimal point position: after (len(ip) - lead) integer digits, shifted by exp
    n = (len(ip) - lead) + exp  # ES6 'n': value = s * 10^(n - k)
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        # exponential notation
        mant_out = s[0] + ("." + s[1:] if k > 1 else "")
        e = n - 1
        out = f"{mant_out}e{'+' if e >= 0 else ''}{e}"
    return sign + out


def _jcs_escape(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ES6_SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_string(value: str) -> str:
    return _jcs_escape(value)


def _jcs_serialize(obj) -> str:
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if obj is None:
        return "null"
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, (int, float)):
        return _es6_number_to_string(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_jcs_serialize(v) for v in obj) + "]"
    if isinstance(obj, dict):
        # RFC 8785 §3.2.3: order by UTF-16 code units — big-endian UTF-16 bytes
        # compare exactly in code-unit order.
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_jcs_string(k)}:{_jcs_serialize(v)}" for k, v in items) + "}"
    raise TypeError(f"type not serializable in JCS: {type(obj)!r}")


def jcs(obj) -> bytes:
    """RFC 8785 canonical JSON bytes."""
    return _jcs_serialize(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def load_pubkey() -> bytes:
    return serialization.load_pem_public_key(PUB_PATH.read_bytes())


def verify_receipt(path: Path, pub) -> dict:
    """Verify one pilot receipt. Returns a structured result dict."""
    res = {"file": str(path), "checks": [], "passed": True, "reason": None}
    try:
        env = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        res["passed"] = False
        res["reason"] = f"load error: {exc}"
        return res
    if not isinstance(env, dict) or "payload" not in env or "signature_hex" not in env:
        res["passed"] = False
        res["reason"] = "envelope missing payload/signature_hex"
        return res
    payload = env["payload"]
    try:
        canonical = jcs(payload)
    except Exception as exc:
        res["passed"] = False
        res["reason"] = f"canonicalization error: {exc}"
        return res

    # 1) canonical_hex pin must match the recomputation from source JSON
    pinned_hex = env.get("canonical_hex", "")
    hex_match = canonical.hex() == pinned_hex
    res["checks"].append(
        ("canonical_hex:matches-recompute", hex_match,
         "canonical_hex equals JCS recompute from payload" if hex_match
         else "canonical_hex differs from JCS recompute (canonicalizer divergence)")
    )

    # 2) signature must verify over the RECOMPUTED bytes (not the pinned hex)
    try:
        sig = bytes.fromhex(env["signature_hex"])
        pub.verify(sig, canonical)
        sig_ok = True
        sig_detail = "Ed25519 valid over recomputed JCS bytes"
    except InvalidSignature:
        sig_ok = False
        sig_detail = "Ed25519 INVALID over recomputed JCS bytes (tamper detected)"
    except Exception as exc:
        sig_ok = False
        sig_detail = f"signature error: {exc}"
    res["checks"].append(("signature:ed25519", sig_ok, sig_detail))

    res["passed"] = hex_match and sig_ok
    if not res["passed"]:
        res["reason"] = sig_detail if not sig_ok else "canonical_hex mismatch"
    res["canonical"] = canonical
    res["payload"] = payload
    return res


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_manifest(manifest_path: Path, root: Path) -> tuple[list, bool]:
    """Closed-inventory validation, both directions."""
    problems: list[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pinned = manifest.get("files", {})
    for rel in sorted(pinned):
        f = root / rel
        if not f.is_file():
            problems.append(f"manifest pins missing file: {rel}")
            continue
        actual = sha256_file(f)
        if actual != pinned[rel]:
            problems.append(
                f"digest mismatch: {rel} manifest={pinned[rel][:12]}.. actual={actual[:12]}.."
            )
    pinned_set = set(pinned)
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.name == "manifest.json":
            continue
        rel = f.relative_to(root).as_posix()
        if rel not in pinned_set:
            problems.append(f"unpinned file present in inventory: {rel}")
    return problems, True


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(__doc__)
        return 2

    pub = load_pubkey()

    # ---- legacy single-receipt mode -------------------------------------
    if len(argv) == 2:
        r = verify_receipt(Path(argv[1]), pub)
        for name, ok, detail in r["checks"]:
            print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        if r["passed"]:
            p = r.get("payload", {})
            print(
                f"VALID — signature binds payload: {p.get('case_id')} {p.get('verdict')}"
            )
            return 0
        print("INVALID — verification FAILED")
        return 1

    # ---- batch mode ------------------------------------------------------
    fixtures_dir = HERE / "fixtures"
    manifest_path = HERE / "manifest.json"

    inv_problems, _ = verify_manifest(manifest_path, HERE)
    for p in inv_problems:
        print(f"[FAIL] inventory: {p}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pinned_receipts = sorted(
        rel for rel in manifest.get("files", {})
        if rel.startswith("fixtures/") and rel.endswith(".json")
    )
    if not pinned_receipts:
        print("[FAIL] manifest pins no fixture receipts")
        return 1

    results = []
    for rel in pinned_receipts:
        results.append(verify_receipt(HERE / rel, pub))

    # contract: C1-C4/C6 valid, C5 tampered-invalid
    CONTRACT = {
        "case-C1-receipt.json": True,
        "case-C2-receipt.json": True,
        "case-C3-receipt.json": True,
        "case-C4-receipt.json": True,
        "case-C5-tampered-receipt.json": False,
        "case-C6-replay-copy.json": True,
    }
    contract_ok = True
    for r in results:
        name = Path(r["file"]).name
        want = CONTRACT.get(name)
        if want is None:
            continue
        if r["passed"] != want:
            contract_ok = False
            print(
                f"[FAIL] contract: {name} verified={r['passed']} expected={want}"
            )
        else:
            tag = "valid-by-contract" if want else "invalid-by-contract"
            print(f"[PASS] contract: {name} ({tag})")

    # cross-submission duplicate (replay) detection over canonical payloads
    by_canonical: dict[bytes, list[str]] = {}
    for r in results:
        by_canonical.setdefault(r["canonical"], []).append(Path(r["file"]).name)
    replay_groups = {c: names for c, names in by_canonical.items() if len(names) > 1}
    for c, names in sorted(by_canonical.items(), key=lambda kv: kv[1][0]):
        if len(names) > 1:
            print(
                "[WARN] replay-candidate group (identical canonical payload, "
                f"correlation layer must dedupe): {', '.join(sorted(names))}"
            )

    # footer totals recomputed from the manifest (self-proving-total rule)
    total_pinned = len(manifest.get("files", {}))
    inventory_ok = not inv_problems
    batch_ok = all(r["passed"] == CONTRACT.get(Path(r["file"]).name, r["passed"])
                   for r in results) and contract_ok
    print("=" * 60)
    print(f"Manifest files pinned:  {total_pinned}")
    print(f"Receipts verified:      {len(results)}")
    print(f"Inventory:              {'CLOSED-OK' if inventory_ok else 'BROKEN'}")
    print(f"Contract C1-C6:         {'MET' if contract_ok else 'VIOLATED'}")
    if not (inventory_ok and batch_ok):
        print("✗ PILOT VERIFICATION FAILED")
        return 1
    print("✓ PILOT VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
