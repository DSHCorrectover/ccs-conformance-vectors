# BoundaryAttest side (owner: @cullenmeyers)

This directory contains the BoundaryAttest-native receipt independently mapped
from `../../event.json`. It uses the unchanged BoundaryAttest Interop Profile
v0.1 envelope:

```json
{
  "claim": {},
  "signature": "base64-ed25519-signature",
  "public_key_id": "sha256:<SPKI-DER-SHA-256>"
}
```

All fixture-specific extensions are inside `claim` and covered by the
signature. There are no CCS signing or verification imports.

This fixture intentionally preserves Interop Profile v0.1 for legacy
verification. Profile v0.1 is frozen; new BoundaryAttest external integrations
target Interop Profile v0.2. This historical fixture does not make v0.1 the
recommended profile for new integrations.

## Reproduce and verify

From this directory, using Python 3 with `cryptography` installed:

```bash
python3 build_boundaryattest_receipt.py
python3 verify_boundaryattest_receipt.py
```

The verifier reads `public-key.pem` independently from the receipt. A real
relying party must obtain its expected public key through a trusted path; a key
shipped next to an untrusted receipt does not establish trust.

## Fixture key warning

The Ed25519 key is deterministic and **TEST-ONLY**. The builder hashes the
published label
`BoundaryAttest paired fixture 01-deny TEST-ONLY Ed25519 key v1` to obtain the
32-byte fixture seed. This is intentionally public and reproducible key
material, not a secret, private-key file, production key, or key-custody model.
Never reuse this key outside this fixture.

Only the public SPKI PEM is written to disk. The receipt's `public_key_id` is
`sha256:` followed by the lowercase SHA-256 digest of that SPKI DER encoding.

## Claim semantics

`receipt_role` is `server_attested` because the synthetic signer represents the
local admission gate/runtime attesting to the decision evidence it produced.
It does not mean the requested command ran. The claim records a denied
`shell.exec.admission_decision`, sets `executed` to `false` and `output_hash` to
`null`, and describes the signed event as `gate.decision.evidence_exported`.

The required `timestamp` is the later `evidence_exported_at` instant. The
original gate decision remains separately bound as `decided_at`.

`args_digest` is lowercase raw SHA-256 hex over the exact parsed
`request.arguments`, canonicalized with the BoundaryAttest v0.1 stableJson
rules. `input_hash` carries the same value as `sha256:<hex>`. `event_digest` is
similarly SHA-256 over the entire parsed neutral event under stableJson; both
algorithm labels are explicit signed adapter fields.

The policy reference, version, digest, and digest algorithm are copied exactly
from the neutral event. The independent verifier additionally proves that the
policy digest is SHA-256 over the exact UTF-8 bytes of `policy_text`.

Passing verification establishes envelope, expected-key, signature, and
fixture-binding integrity only. It does not prove the claim true, the signer
trustworthy, the decision authorized, or the runtime uncompromised.
