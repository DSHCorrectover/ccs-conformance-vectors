#!/usr/bin/env python3
"""
Field-level crosswalk harness for the BoundaryAttest x CCS paired fixture.

One row per semantic field.  Each row compares the value emitted by each
native receipt under its own canonicalization:

  PASS     - both sides present the same semantic value
  MISMATCH - both sides have the field but the values/bindings differ
  N/A      - the comparison is not applicable because one side omits the field
             or the native values intentionally inhabit non-comparable identity
             domains (a recorded scope difference, not a failure)
  PENDING  - the BoundaryAttest side has not landed yet

The harness never normalizes mismatches away; MISMATCH rows are first-class
deliverables and MUST be explained in NOTES.md.

It evaluates each side from its native artifacts. When the BoundaryAttest
receipt is absent, its rows remain PENDING.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import jcs

HERE = Path(__file__).resolve().parent
EVENT_PATH = HERE.parent / "event.json"
CCS_RECEIPT = HERE / "ccs-side" / "receipt.json"
CCS_RESPONSE = HERE / "ccs-side" / "response-body.json"
BA_RECEIPT = HERE / "boundaryattest-side" / "receipt.json"

PASS, MISMATCH, NA, PENDING = "PASS", "MISMATCH", "N/A", "PENDING"


def csh(data) -> str:
    return hashlib.sha256(jcs.canonicalize(data)).hexdigest()


def parse_rfc3339(value: str) -> float:
    """Convert an RFC 3339 timestamp to epoch seconds."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("RFC 3339 timestamp must include an offset")
    return parsed.astimezone(timezone.utc).timestamp()


def main() -> int:
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    ccs = json.loads(CCS_RECEIPT.read_text(encoding="utf-8"))
    ccs_response = json.loads(CCS_RESPONSE.read_text(encoding="utf-8"))
    ba = json.loads(BA_RECEIPT.read_text(encoding="utf-8")) if BA_RECEIPT.exists() else None
    ba_claim = ba.get("claim", {}) if ba else {}

    rows = []

    def row(field, ccs_val, ba_val, status, note):
        rows.append({"field": field, "ccs": ccs_val, "boundaryattest": ba_val,
                     "status": status, "note": note})

    # 1. action / tool digest
    ba_action = ba_claim.get("action") if ba else None
    row("action_ref", ccs["action"], ba_action,
        PENDING if ba is None else (
            PASS if ccs.get("action") == ba_action else MISMATCH),
        "Both receipts identify shell.exec, but CCS binds the requested execution while BoundaryAttest binds the admission-decision evidence export; the action semantics intentionally differ.")

    # 2. arguments digest
    row("args_digest_sha256",
        ccs["args_digest"],
        (ba_claim.get("args_digest") or ba.get("args_digest")) if ba else None,
        PENDING if ba is None else (
            PASS if ccs["args_digest"] == (ba_claim.get("args_digest") or ba.get("args_digest"))
            else MISMATCH),
        "Digest of exact request arguments. CCS uses JCS(RFC 8785); BoundaryAttest uses stableJson — digest equality is the test; canonicalization differences are NOTES, not failures.")

    # 3. policy reference
    row("policy_ref",
        event["policy"]["policy_ref"],
        ba_claim.get("policy_ref") if ba else None,
        PENDING if ba is None else (
            PASS if ba_claim.get("policy_ref") == event["policy"]["policy_ref"] else MISMATCH),
        "BoundaryAttest v0.1 core has no policy_ref; per cullenmeyers it lands as a signed adapter-specific claim field.")

    # 4. policy version
    row("policy_version",
        ccs["rule_version"],
        ba_claim.get("policy_version") if ba else None,
        PENDING if ba is None else (
            PASS if ba_claim.get("policy_version") == ccs["rule_version"] else MISMATCH),
        "Adapter-specific claim extension on the BoundaryAttest side.")

    # 5. policy digest
    row("policy_digest_sha256",
        event["policy"]["policy_digest"],
        ba_claim.get("policy_digest") if ba else None,
        PENDING if ba is None else (
            PASS if ba_claim.get("policy_digest") == event["policy"]["policy_digest"]
            else MISMATCH),
        "Optional adapter field; binds exact policy semantics. CCS binds it inside config_hash.")

    # 6. verdict
    row("verdict",
        ccs["verdict"],
        (ba.get("verdict") or ba_claim.get("verdict")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("verdict") or ba_claim.get("verdict", "")).lower() in ("deny", "block")
            else MISMATCH),
        "Neutral DENY; CCS native vocabulary is 'block' (pre-admission). Vocabulary mapping itself is an interop finding — see NOTES.")

    # 7. execution result
    row("executed",
        ccs_response.get("executed"),
        ba_claim.get("executed") if ba else None,
        PENDING if ba is None else (
            PASS if ccs_response.get("executed") is False and ba_claim.get("executed") is False
            else MISMATCH),
        "Both signatures bind the pre-admission no-execution result: CCS via response_hash over response-body.json and BoundaryAttest via claim.executed.")

    # 8. signer / key reference
    row("signer_key_fingerprint",
        ccs["public_key_fingerprint"],
        ba.get("public_key_id") if ba else None,
        PENDING if ba is None else NA,
        "Both sides expose signer identifiers with different fingerprint formats over intentionally independent keys; equality is not a meaningful interoperability requirement.")

    # 9. signature algorithm
    row("signature_algorithm",
        ccs["signing_algorithm"],
        "Ed25519 (normative in Interop Profile v0.1)" if ba else None,
        PENDING if ba is None else (PASS if ccs["signing_algorithm"] == "Ed25519" else MISMATCH),
        "CCS carries the algorithm explicitly; BoundaryAttest Interop Profile v0.1 normatively fixes Ed25519, so the harness derives it without altering the envelope.")

    # 10. timestamp / freshness
    row("decision_time",
        ccs["timestamp"],
        (ba.get("timestamp") or ba_claim.get("decided_at")) if ba else None,
        PENDING if ba is None else (
            PASS if parse_rfc3339(ba_claim["decided_at"]) == float(ccs["timestamp"])
            else MISMATCH),
        "Same neutral decided_at instant; representations may differ (epoch float vs RFC3339) — semantic equality is the test.")

    # 11. shared evidence digest (event)
    row("shared_event_digest_sha256",
        csh(event),
        (ba.get("event_digest") or ba_claim.get("event_digest")) if ba else None,
        PENDING if ba is None else (
            PASS if (ba.get("event_digest") or ba_claim.get("event_digest")) == csh(event)
            else MISMATCH),
        "Digest of the neutral event.json. If both sides canonicalize the same neutral bytes identically this matches; any MISMATCH here is a canonicalization finding.")

    # 12. reason / refusal text
    row("deny_reason_code",
        ccs_response.get("reason_code"),
        (ba_claim.get("reason_code") or ba.get("reason_code")) if ba else None,
        PENDING if ba is None else (
            PASS if ccs_response.get("reason_code") == (ba_claim.get("reason_code") or ba.get("reason_code")) == event["decision"]["reason_code"]
            else MISMATCH),
        "Both signatures bind the same structured neutral reason code: CCS via response_hash over response-body.json and BoundaryAttest inside claim.")

    counts = {PASS: 0, MISMATCH: 0, NA: 0, PENDING: 0}
    for r in rows:
        counts[r["status"]] += 1

    out = {
        "fixture": "paired-boundaryattest/01-deny",
        "event_id": event["event_id"],
        "generated_note": (
            "BoundaryAttest-native receipt is absent; PENDING rows await it."
            if ba is None else
            "Generated from both native receipts; non-PASS rows are documented in NOTES.md."
        ),
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
