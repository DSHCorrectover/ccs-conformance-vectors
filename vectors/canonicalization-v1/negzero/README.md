# negzero — RFC 8785 integer negative zero (numeric + string members)

## What this case pins

The wire JSON text in `input.json` is exactly (UTF-8, no BOM, single LF):

```
{"n":-0,"s":"-0"}
```

It carries **two separate members**:

| Key | JSON type | Wire token | Expected canonical member |
| --- | --- | --- | --- |
| `n` | number | integer `-0` (no decimal/exponent; not the IEEE-754 negative-zero float) | `"n":0` |
| `s` | string | `"-0"` (the string form of the signed digit) | `"s":"-0"` |

The integer token `-0` and the string `"-0"` are carried as two separate
members to distinguish a numeric value from its string form: the next
conflation after the `-0`/`0` one sits between a numeric value and its string
form. Under RFC 8785 (JCS) the numeric member canonicalises to `0` while the
string member is preserved verbatim with its quotes; object members are
serialized in lexicographic key order (`n` before `s`). The canonical form is
therefore:

```
{"n":0,"s":"-0"}
```

| Item | Value |
| --- | --- |
| Input (raw JSON text, on disk plus one LF) | `{"n":-0,"s":"-0"}` |
| Expected canonical UTF-8 | `{"n":0,"s":"-0"}` |
| Expected canonical hex | `7b226e223a302c2273223a222d30227d` |
| Expected canonical SHA-256 | `157e197979b3c77179009f0861fa10c8ecddc034ab18b4ed06847227f4823287` |
| Rejected literal UTF-8 | `{"n":-0,"s":"-0"}` |
| Rejected literal hex | `7b226e223a2d302c2273223a222d30227d` |
| Rejected literal SHA-256 | `dc67e8bd73223949d550892a03ff5f44aec87a9adff54105af914194ce2cf02e` |
| Confusion A (string coerced to number) | `{"n":0,"s":0}` |
| Confusion A hex | `7b226e223a302c2273223a307d` |
| Confusion A SHA-256 | `cfbad07b1e2b53a78a1ba66bb31fa4fb5054786defae4f0adcdb329dd15bbb03` |
| Confusion B (member types swapped) | `{"n":"-0","s":-0}` |
| Confusion B hex | `7b226e223a222d30222c2273223a2d307d` |
| Confusion B SHA-256 | `d884405a99c4d7c4ff9ba2424f6e05b3999f48a9ffcb9b36b9dafbd41cd07e44` |
| Signing algorithm | Ed25519 over the canonical bytes |
| Public key (base64) | `ndAkiPndnKQ7hLAMOQBu4BE79y0BM3NA0diA0YDB2cI=` |
| Public key fingerprint | `26a02d86f5d0a10f` |

## Why the input is raw JSON text

The fixture deliberately preserves the original wire bytes in `input.json`.
CPython's own JSON parser already normalizes the integer `-0` token to `0`
(`json.loads` yields `{"n": 0, "s": "-0"}`; the string survives as a
distinct `str`), so parsing the text into a host object and re-serializing it
erases the numeric literal before canonicalization can be observed. That is
the *correct* outcome, but it means the divergence between conformant and
literal-preserving implementations cannot be shown with parsed values alone.
The discriminator is signature evidence over the exact preimage bytes:

* `signature.sig` — Ed25519 signature over the canonical bytes `{"n":0,"s":"-0"}`
  (hex `7b226e223a302c2273223a222d30227d`).
* `negative-signature.sig` — Ed25519 signature over the rejected literal
  bytes `{"n":-0,"s":"-0"}` (hex `7b226e223a2d302c2273223a222d30227d`). The rejected literal is byte-identical to
  the raw wire text without its trailing LF: a literal-preserving
  implementation effectively signs the wire literal instead of the
  canonical form.
* `confusion-string-as-number.json` — `{"n":0,"s":0}`: the string member coerced to a
  number.
* `confusion-types-swapped.json` — `{"n":"-0","s":-0}`: numeric/string value types
  swapped between the two members.

## Pass/fail semantics

An implementation is **valid-for-rfc8785** for this case only if:

1. It canonicalizes the raw input text to `{"n":0,"s":"-0"}` — numeric member `n`
   emitted as `0`, string member `s` emitted verbatim as `"-0"`, members
   ordered `n` then `s` — and hashes/signs those bytes;
2. `signature.sig` verifies against the public key over the canonical bytes;
3. `signature.sig` **fails** verification over `{"n":-0,"s":"-0"}` — an implementation
   that preserves the `-0` literal in its signing preimage cannot verify the
   correct signature and must be rejected;
4. `signature.sig` **fails** over both confusion preimages (`{"n":0,"s":0}` and
   `{"n":"-0","s":-0}`) — an implementation that coerces the string member to a number or
   swaps the numeric/string member types must likewise be rejected;
5. `negative-signature.sig` **fails** over the canonical bytes and over both
   confusion preimages, and verifies only over the rejected literal bytes;
6. this `signature.sig` is **different** from `../pluszero/signature.sig`,
   because the two cases sign different canonical preimages
   (`"-0"` vs `"0"` in the string member).

## Reproducing

```sh
python scripts/generate_canonicalization_vectors.py
python checkers/independent_checker.py vectors/canonicalization-v1/
```

