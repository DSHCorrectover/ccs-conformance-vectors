# AER-1 ↔ CCS crosswalk fixture pair

Two receipts, one canonical scheme, one key. Built so `aer1-verify` (or any
verifier) can exercise a **live Ed25519 signature path** against CCS-format
bytes — the path the AER-1 v1.5.7 corpus leaves unexercised
(`verification_scope: sha256_commitment_only`).

## Contents

| dir | expected outcome | what it tests |
|---|---|---|
| `01-allow/` | signature **VERIFIES** | well-formed receipt, signature binds the full field set |
| `02-tamper-deny/` | signature **REJECTS** (or digest-binding fails) | `response_hash` swapped after signing — the classic "receipt says X, bytes say Y" tamper |

Both receipts are identical except `trace_id`/`_id`/`nonce` and the post-sign
`response_hash` swap in 02.

## Encoding (measured, both schemes agree)

- `canonical_bytes` / signed preimage: **standard-alphabet, padded, non-urlsafe
  base64** — same spelling the AER-1 corpus carries (verified 2026-11-18).
- Signed preimage: **JCS (RFC 8785) canonicalization of the receipt minus the
  `signature` field**.
- Signature: **Ed25519**, base64 standard padded, in the `signature` field.
- `public_key`: base64 of the raw 32-byte Ed25519 public key.
- Key fingerprint: first 16 hex chars of SHA-256 over the SPKI DER pubkey.

## Replay (works verbatim; stdlib + `jcs` + `cryptography` only)

```python
import json, base64, jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def replay(path):
    r = json.load(open(path))
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(r['public_key']))
    signed = {k: v for k, v in r.items() if k != 'signature'}
    try:
        pub.verify(base64.b64decode(r['signature']), jcs.canonicalize(signed))
        return 'VERIFIED'
    except InvalidSignature:
        return 'REJECTED'

print('01-allow:', replay('fixtures/aer1-crosswalk/01-allow/receipt.json'))       # VERIFIED
print('02-tamper-deny:', replay('fixtures/aer1-crosswalk/02-tamper-deny/receipt.json'))  # REJECTED
```

## AER-1 field mapping (for cross-scheme reading)

| AER-1 receipt | CCS receipt equivalent |
|---|---|
| `canonical_bytes` (b64) | JCS canonical form of the receipt minus `signature` (see `01-allow/canonical-bytes.txt`) |
| `output_hash` | digest of the same canonical bytes (`sha256:` + hex) |
| `verification_status` | `verdict` (ALLOW/DENY) |
| — | Ed25519 `signature` + `public_key` + fingerprint (the path this pair adds) |

## Key provenance

Dedicated fixture key, generated 2026-11-18, used for nothing else.
Public key fingerprint: `acda9914178fa44a`.
