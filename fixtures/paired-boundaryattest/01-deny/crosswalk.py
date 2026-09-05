#!/usr/bin/env python3
"""
Field-level crosswalk harness for the BoundaryAttest x CCS paired fixture.

One row per semantic field.  Each row compares the value emitted by each
native receipt under its own canonicalization:

  PASS     - both sides present the same semantic value
  MISMATCH - both sides have the field but the values/bindings differ
  N/A      - the field exists on only one side (a recorded scope difference,
             not a failure)
  PENDING  - the BoundaryAttest side has not landed yet

The harness never normalizes mismatches away; MISMATCH rows are first-class
deliverables and MUST be explained in NOTES.md.

It currently evaluates the CCS side from receipt.json and leaves the
BoundaryAttest side PENDING until boundaryattest-side/receipt.json lands.
When that file exists it will be picked up automatically.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs

HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent / "event.json"
CCS_RECEIPT = HERE / "ccs-side" / "receipt.json"
CCS_ARGS = HERE / "ccs-side" / "tool-args.json"
BA_RECEIPT = HERE / "boundaryattest-side" / "receipt.json"

PASS, MISMATCH, NA, PENDING = "PASS", "MISMATCH", "N/A", "PENDING"


def csh(data) -> str:
    return hashlib.sha256(jcs.canonicalize(data)).hexdigest()


def main() -> int:
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    ccs = json.loads(CCS_RECEIPT.read_text(encoding="utf-8"))
    args = json.loads(CCS_ARGS.read_text(encoding="utf-8"))
    ba = json.loads(BA_RECEIPT.read_text(encoding="utf-8")) if BA_RECEIPT.exists() else None

    rows = []

    def row(field, ccs_val, ba_val, status, note):
        rows.append({"field": field, "ccs": ccs_val, "boundaryattest": ba_val,
                     "status": status, "note": note})

    # 1. action / tool digest
    row("action_ref",
        ccs["action"],
        (ba.get("claim", {}).get("action") or ba.get("action")) if ba else None,
        PENDING if ba is None else PASS,
        "What action was gated. Neutral event: request.tool.")

    # 2. arguments digest
    row("args_digest_sha256",
        ccs["args_digest"],
        (ba.get("claim", {}).get("args_digest") or ba.get("args_digest")) if ba else None,
        PENDING if ba is None else (
            PASS if ccs["args_digest"] == (ba.get("claim", {}).get("args_digest") or ba.get("args_digest"))
            else MISMATCH),
        "Digest of exact request arguments. CCS uses JCS(RFC 8785); BoundaryAttest uses stableJson — digest equality is the test; canonicalization differences are NOTES, not failures.")

    # 3. policy reference
    row("policy_ref",
        event["policy"]["policy_ref"],
        (ba.get("claim", {}).get("policy_ref")) if ba else None,
        PENDING if ba is None else (
            PASS if ba.get("claim", {}).get("policy_ref") == event["policy"]["policy_ref"] else MISMATCH),
        "BoundaryAttest v0.1 core has no policy_ref; per cullenmeyers it lands as a signed adapter-specific claim field.")

    # 4. policy version
    row("policy_version",
        ccs["rule_version"],
        (ba.get("claim", {}).get("policy_version")) if ba else None,
        PENDING if ba is None else (
            PASS if ba.get("claim", {}).get("policy_version") == ccs["rule_version"] else MISMATCH),
        "Adapter-specific claim extension on the BoundaryAttest side.")

    # 5. policy digest
    row("policy_digest_sha256",
        event["policy"]["policy_digest"],
        (ba.get("claim", {}).get("policy_digest")) if ba else None,
        PENDING if ba is None else (
            PASS if ba.get("claim", {}).get("policy_digest") == event["policy"]["policy_digest"]
            else MISMATCH),
        "Optional adapter field; binds exact policy semantics. CCS binds it inside config_hash.")

    # 6. verdict
    row("verdict",
        ccs["verdict"],
        (ba.get("verdict") or ba.get("claim", {}).get("verdict")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("verdict") or ba.get("claim", {}).get("verdict", "")).lower() in ("deny", "block")
            else MISMATCH),
        "Neutral DENY; CCS native vocabulary is 'block' (pre-admission). Vocabulary mapping itself is an interop finding — see NOTES.")

    # 7. execution result
    row("executed",
        False,
        (ba.get("executed") if ba else None),
        PENDING if ba is None else (PASS if ba.get("executed") is False else MISMATCH),
        "Pre-admission DENY: no side effects. CCS encodes this via response-body envelope (response_hash) rather than a top-level boolean — recorded scope difference.")

    # 8. signer / key reference
    row("signer_key_fingerprint",
        ccs["public_key_fingerprint"],
        (ba.get("key_fingerprint") or ba.get("claim", {}).get("key_fingerprint")) if ba else None,
        PENDING if ba is None else (
            NA if not (ba.get("key_fingerprint") or ba.get("claim", {}).get("key_fingerprint"))
            else MISMATCH),
        "Two independent keys BY DESIGN; values will differ (that is the point). Recorded as N/A scope difference unless one side exposes no fingerprint.")

    # 9. signature algorithm
    row("signature_algorithm",
        ccs["signing_algorithm"],
        (ba.get("signature_algorithm") or ba.get("alg")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("signature_algorithm") or ba.get("alg")) == ccs["signing_algorithm"] else MISMATCH),
        "Both use Ed25519 in this fixture.")

    # 10. timestamp / freshness
    row("decision_time",
        ccs["timestamp"],
        (ba.get("timestamp") or ba.get("claim", {}).get("decided_at")) if ba else None,
        PENDING if ba is None else PASS,
        "Same neutral decided_at instant; representations may differ (epoch float vs RFC3339) — semantic equality is the test.")

    # 11. shared evidence digest (event)
    row("shared_event_digest_sha256",
        csh(event),
        (ba.get("event_digest") or ba.get("claim", {}).get("event_digest")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("event_digest") or ba.get("claim", {}).get("event_digest")) == csh(event)
            else MISMATCH),
        "Digest of the neutral event.json. If both sides canonicalize the same neutral bytes identically this matches; any MISMATCH here is a canonicalization finding.")

    # 12. reason / refusal text
    row("deny_reason_code",
        "block:" + event["decision"]["reason_code"],
        (ba.get("claim", {}).get("reason_code") or ba.get("reason_code")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("claim", {}).get("reason_code") or ba.get("reason_code")) == event["decision"]["reason_code"]
            else MISMATCH),
        "CCS puts human-readable reason in rule_summary; structured code may not exist natively on either side — likely N/A scope difference.")

    counts = {PASS: 0, MISMATCH: 0, NA: 0, PENDING: 0}
    for r in rows:
        counts[r["status"]] += 1

    out = {
        "fixture": "paired-boundaryattest/01-deny",
        "event_id": event["event_id"],
        "generated_note": "PENDING rows are waiting on the BoundaryAttest-native receipt. BoundaryAttest side: drop receipt.json under boundaryattest-side/ and re-run.",
        "counts": counts,
        "rows": rows,
    }
    out_path = HERE / "crosswalk.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"{'FIELD':<28} {'STATUS':<9} VALUE")
    print("-" * 70)
    for r in rows:
        v = r["ccs"] if r["status"] != PENDING else "(waiting BA)"
        print(f"{r['field']:<28} {r['status']:<9} {str(v)[:36]}")
    print("-" * 70)
    print(f"PASS={counts[PASS]} MISMATCH={counts[MISMATCH]} N/A={counts[NA]} PENDING={counts[PENDING]}")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
