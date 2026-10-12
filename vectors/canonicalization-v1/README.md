# canonicalization-v1 — JCS (RFC 8785) numeric boundary vectors

This sub-corpus pins down [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
(JSON Canonicalization Scheme, JCS) canonicalization behavior at JSON
numeric boundary conditions. It is independent of the signed-receipt
corpus in `../v1.4.0-conformance/` and has its own `manifest.json`; nothing
under that directory is touched or re-pinned here.

The case set:

| Case | Raw wire input | Expected canonical | Boundary |
| --- | --- | --- | --- |
| `negzero/` | `{"n":-0,"s":"-0"}` | `{"n":0,"s":"-0"}` | integer token `-0` is serialized as `0`; string `"-0"` preserved verbatim |
| `pluszero/` | `{"n":0,"s":"0"}` | `{"n":0,"s":"0"}` | baseline: plain `0` / `"0"`; distinct preimage from negzero |

## Separate numeric and string members

Every input document carries two **independent members**: a numeric member
`n` and a string member `s` carrying the string form of the signed digit.
The integer token `-0` and the string `"-0"` are carried as two separate
members to distinguish a numeric value from its string form — the next
conflation after the `-0`/`0` one sits between a numeric value and its
string form. Under RFC 8785 the numeric member canonicalises to `0` while
JSON strings are serialized verbatim and are not numerically normalized,
so the two cases produce two **different** canonical preimages
(`{"n":0,"s":"-0"}` vs `{"n":0,"s":"0"}`) and two different signatures.

Each case's `expected.json` states the expected canonical form **per
member** (`"n":0` vs `"s":"-0"`/`"s":"0"`, the string shown with its
quotes) and at the whole-document level (UTF-8, hex, and SHA-256), so a
failing implementation can see exactly what it should have produced.

## Pinned wrong preimages

Two classes of non-conformant implementation are pinned with exact bytes:

* **rejected literal** `{"n":-0,"s":"-0"}` (hex `7b226e223a2d302c2273223a222d30227d`, file under `negzero/`) —
  the preimage of a canonicalizer that preserves the integer `-0` token.
  For the negzero case these bytes are identical to the raw wire text
  without its trailing LF, i.e. the non-conformant implementation signs
  the wire literal as if it were canonical;
* **numeric/string confusion**:
  `{"n":0,"s":0}` (hex `7b226e223a302c2273223a307d`) — the string member coerced to a number, shipped
  for both cases as `confusion-string-as-number.json`; and
  `{"n":"-0","s":-0}` (hex `7b226e223a222d30222c2273223a2d307d`, under `negzero/`) — the numeric/string value
  types swapped between the members.

Signature evidence is bidirectional for negzero:

* `negzero/signature.sig` is VALID only over `{"n":0,"s":"-0"}` and INVALID over
  the rejected literal and every confusion preimage;
* `negzero/negative-signature.sig` is VALID only over the rejected literal
  and INVALID over the canonical bytes and every confusion preimage;
* `pluszero/signature.sig` is VALID only over `{"n":0,"s":"0"}`, INVALID over
  the rejected literal and all confusion preimages, and is a different
  signature from the negzero one (different preimages).

## Inputs are raw JSON text

Each case keeps the **original wire JSON text** in `input.json` (UTF-8, no
BOM, single trailing LF). The signed preimage is the canonical JSON bytes
listed in `expected.json`; the trailing LF in the on-disk input is never
part of a signing preimage.

This matters because host parsers may normalize numeric tokens before an
application-level canonicalizer ever sees them — CPython, for example,
parses the integer `-0` token to `0` while leaving the string `"-0"`
untouched. The fixtures therefore (1) freeze the wire text on disk and (2)
provide signature evidence that proves, against the public key alone,
whether an implementation built its preimage from the canonical bytes, from
the rejected literal, or from a numeric/string-conflated document.

## Signing material

* Algorithm: Ed25519 over the JCS canonical bytes.
* Deterministic public conformance key (same recipe as the rest of the
  repository):

  ```
  seed      = SHA-256(b"ccs-conformance-vectors/v1/independent-checker")
  public key (base64) = ndAkiPndnKQ7hLAMOQBu4BE79y0BM3NA0diA0YDB2cI=
  fingerprint         = 26a02d86f5d0a10f
  ```

  The seed is public corpus data for reproducibility, not a secret.
* `signature.sig` holds the raw 64-byte Ed25519 signature; base64 of the
  same bytes is recorded in `expected.json` as `signature_b64`.
* `negzero/negative-signature.sig` signs the rejected literal bytes
  `{"n":-0,"s":"-0"}` and exists solely to demonstrate the preimage divergence.
* The two cases sign different canonical preimages, so their
  `signature.sig` files are different bytes.

## Conformance semantics

* `expect: valid-for-rfc8785` means the raw input must canonicalize to the
  pinned canonical bytes and the positive signature must verify over them.
* An implementation that preserves the integer `-0` literal and constructs
  `{"n":-0,"s":"-0"}` as its signing preimage is **non-conformant**: `signature.sig`
  fails verification over that preimage. Conversely `negative-signature.sig`
  fails over the correct canonical bytes and verifies only over the
  rejected literal.
* An implementation that conflates the numeric value with its string form
  (coercing the string member to a number or swapping the member types) is
  likewise **non-conformant**: `signature.sig` fails over each confusion
  preimage.

## Reproducing

```sh
# Regenerate every file (deterministic; idempotent)
python scripts/generate_canonicalization_vectors.py

# Independently verify
python checkers/independent_checker.py vectors/canonicalization-v1/
```

All data in this directory is CC0 1.0 Universal (public domain).

