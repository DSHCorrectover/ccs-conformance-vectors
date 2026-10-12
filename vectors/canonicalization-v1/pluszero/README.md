# pluszero — plain zero baseline (numeric + string members)

`input.json` is the raw JSON text `{"n":0,"s":"0"}` (UTF-8, no BOM, single LF),
carrying the same two separate members as `negzero/`: numeric member `n`
(wire token `0`) and string member `s` (wire token `"0"`). It canonicalizes
under RFC 8785 (JCS) to:

| Item | Value |
| --- | --- |
| Input (raw JSON text, on disk plus one LF) | `{"n":0,"s":"0"}` |
| Expected canonical UTF-8 | `{"n":0,"s":"0"}` |
| Expected canonical hex | `7b226e223a302c2273223a2230227d` |
| Expected canonical SHA-256 | `102a43f82ed1d7af790bbf72da81e7fe280875ed2b2e83e1d4952a6a24e58f00` |
| Numeric member canonical form | `"n":0` |
| String member canonical form | `"s":"0"` (quoted; verbatim) |
| Own confusion (string coerced to number) | `{"n":0,"s":0}` |
| Rejected literal (pinned in `../negzero/`) | `{"n":-0,"s":"-0"}` |
| Types-swapped confusion (pinned in `../negzero/`) | `{"n":"-0","s":-0}` |
| Signing algorithm | Ed25519 over the canonical bytes |
| Public key (base64) | `ndAkiPndnKQ7hLAMOQBu4BE79y0BM3NA0diA0YDB2cI=` |
| Public key fingerprint | `26a02d86f5d0a10f` |

This control case demonstrates the ordinary zero/`"0"` baseline. Its
canonical preimage `{"n":0,"s":"0"}` is **different** from the negzero preimage
`{"n":0,"s":"-0"}` (the string member is preserved verbatim, so `"0"` and `"-0"` do
not converge), and therefore `signature.sig` here is a different signature
from `../negzero/signature.sig`. The checker also proves this control
signature is INVALID over the rejected literal `{"n":-0,"s":"-0"}`, over its own
string-as-number confusion `{"n":0,"s":0}`, and over the negzero types-swapped
confusion `{"n":"-0","s":-0}` (files pinned under `../negzero/`).

No `+0` fixture is included: a leading plus sign is not permitted in the
RFC 8259 JSON number grammar, so `{"n":+0}` is not parseable JSON and
cannot serve as a conformance input.

## Reproducing

```sh
python scripts/generate_canonicalization_vectors.py
python checkers/independent_checker.py vectors/canonicalization-v1/
```

