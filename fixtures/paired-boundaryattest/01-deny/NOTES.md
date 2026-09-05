# NOTES — semantic mismatches and scope differences (fixture 01-deny)

Mismatches are first-class deliverables in this exercise: they show where two
independently designed receipt systems bind similar semantics differently.
Nothing here is normalized away.

## Known / expected findings (pre-BoundaryAttest-side)

1. **Verdict vocabulary.** The neutral event uses `DENY`. CCS's native verdict
   vocabulary is `allow / block / escalate`, so the CCS receipt records
   `"verdict": "block"`. BoundaryAttest uses its own claim vocabulary. The
   crosswalk compares semantics (a pre-admission refusal), not strings. The
   vocabulary mapping itself is an interoperability finding: a neutral verdict
   enum may be worth defining in a later interop profile.

2. **Canonicalization.** CCS canonicalizes signed JSON with JCS (RFC 8785);
   BoundaryAttest uses stableJson. Digests over the *same neutral bytes* can
   therefore differ even when the semantic content is identical. The
   `shared_event_digest_sha256` row is the explicit test of this: both sides
   hash the neutral `event.json` as-is (it is already canonical JSON), so a
   MISMATCH there would indicate a digest-input difference rather than a
   canonicalization difference and would be investigated as such.

3. **Policy binding.** BoundaryAttest Interop Profile v0.1 has no universal
   `policy_version` / `policy_digest` core field. Per @cullenmeyers
   (issue #1), these land as **adapter-specific signed claim fields**
   (`policy_ref`, `policy_version`, `policy_digest` inside `claim`, covered by
   the BoundaryAttest signature). On the CCS side the policy version is the
   native `rule_version` field, and `policy_ref` + `policy_digest` are bound
   inside `config_hash` rather than carried as top-level receipt fields.
   Same semantics (signature covers the exact policy), different placement.

4. **"Not executed" representation.** DENY is pre-admission: the tool never
   runs. CCS has no top-level `executed` boolean; it encodes the refusal in a
   response envelope (`response-body.json`: `{"executed": false, ...}`) whose
   digest is `response_hash`. If BoundaryAttest carries `executed`/effect
   semantics natively, that row will likely be PASS on semantics but the field
   *placement* differs — a recorded scope difference.

5. **Signer identity, by design different.** The two receipts use two
   independent keys. `signer_key_fingerprint` will never be equal; the row is
   there to document that the signatures are independently verifiable, not to
   assert equality. Cross-signer trust is out of scope for this fixture.

6. **Timestamp representation.** The neutral event uses RFC 3339 UTC strings.
   The CCS receipt uses epoch seconds (float) for `timestamp` / `issued_at` /
   `verified_at` / `expires_at`. Semantic equality (same instant, within
   `max_clock_skew`) is the test; representation difference is expected.

7. **Reason codes.** The neutral event has structured `reason_code`
   (`POLICY_DENY_SYSTEM_PATH_WRITE`) plus human-readable `reason`. CCS folds
   the human-readable part into `rule_summary`; there is no native structured
   reason-code field in CCS L1. If BoundaryAttest lacks one too, this is a
   mutual gap worth noting for the interop profile.

## Open questions for the BoundaryAttest side

- Does the BoundaryAttest receipt expose an independent `event_digest` over the
  neutral event bytes, or only action/args digests?
- How does BoundaryAttest encode freshness/expiry (the CCS side commits to
  `issued_at` / `expires_at` / `max_clock_skew` inside the signed receipt)?

## Rule for adding findings

Every MISMATCH/N/A row in `crosswalk.json` must have a corresponding entry
here explaining the semantic difference. Crosswalk rows without an explanation
block the fixture from being called complete.
