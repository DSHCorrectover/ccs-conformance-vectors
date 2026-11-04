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

## Rule for adding findings

Every MISMATCH/N/A row in `crosswalk.json` must have a corresponding entry
here explaining the semantic difference. Crosswalk rows without an explanation
block the fixture from being called complete.

## BoundaryAttest-side result

The BoundaryAttest-native receipt is now present. The generated crosswalk has
10 PASS, 1 MISMATCH, 1 N/A, and 0 PENDING rows. The native BoundaryAttest
verifier independently confirms the strict v0.1 envelope, expected-key
fingerprint, Ed25519 signature, neutral-event bindings, and denial/not-executed
semantics.

The preliminary run reported 9 PASS, 2 MISMATCH, and 1 N/A. Targeted harness
fixes removed two false mismatches (`executed` and `signature_algorithm`) and
turned the unconditional `action_ref` PASS into the genuine mismatch below.
This is improved comparison accuracy, not normalization toward a greener
result.

The two non-PASS rows are intentional interoperability findings, not receipt
defects:

1. **`action_ref` — MISMATCH (deliberate claim-scope difference).** Both
   receipts describe the same shared neutral event and identify `shell.exec`,
   but they bind different action-level semantics. CCS represents the
   consequential operation being gated or executed as `shell.exec.execute`.
   BoundaryAttest represents the admission-decision evidence export as
   `shell.exec.admission_decision`. The crosswalk compares those native values
   and does not normalize them into equality. This is a deliberate difference
   in claim scope, not an implementation defect.

2. **`signer_key_fingerprint` — N/A (intentional claim-scope and identity
   difference).** CCS exposes its signer as `public_key_fingerprint` while
   BoundaryAttest exposes an SPKI-DER SHA-256 `public_key_id`. Both references
   are present and independently verified, but the receipts deliberately use
   different signing keys and identifier formats. Equality is therefore not a
   meaningful interoperability requirement. N/A records that this comparison
   is intentionally non-applicable; it does not mean either receipt omitted
   its signer reference.

The corrected PASS rows are mechanically checked: `claim.executed: false`
matches the CCS response body committed by `response_hash`; BoundaryAttest's
normative v0.1 Ed25519 algorithm matches CCS's explicit algorithm; RFC 3339 and
epoch decision times resolve to the same instant; and both signed artifacts
bind the same structured denial reason code.
