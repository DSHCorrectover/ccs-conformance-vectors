# CCS Conformance Vectors

[![CC](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](LICENSE)

Reference conformance test vectors for the **Correctover Conformance Shape (CCS)** receipt specification.

These vectors are **public domain (CC0)**. They exist so independent implementations can verify byte-for-byte interoperability with the [ccs-verifier](https://pypi.org/project/ccs-verifier/) reference implementation.

## What is CCS?

CCS is a seven-dimension runtime verification standard for AI agent tool invocations. Every agent tool call produces a tamper-evident, cryptographically signed receipt (Ed25519 over JCS-canonicalized JSON). The specification is published as an IETF Internet-Draft:

- [draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/)

## Directory Layout

```
vectors/
  v1.1.20/
    reference-signed-001.json   # Reference-signed L1 receipt, byte-reproducible
```

Each versioned directory contains vectors that are verified against that specific ccs-verifier release. The `package_version` field inside each vector indicates the exact release it was generated from.

## Reference Vector: reference-signed-001

- **Issuer**: `ccs-verifier/reference` (deterministic, public test-only key)
- **Seed**: `SHA-256(b"ccs-verifier/reference-issuer/v1")`
- **Public key** (Ed25519, raw 32 bytes, base64): `v63J4PdpUTeDVUuGMgpayNc5ex/ufTmrW+9oKyybbCw=`
- **Key fingerprint** (SHA-256, first 8 bytes hex): `889d3f5bd86f5ff2`
- **Verdict**: `allow`
- **Deployment mode**: `in-process`

This receipt is **byte-reproducible** from the shipped ccs-verifier source. It is NOT a production trust anchor — the seed is publicly known and the key is for conformance testing only.

## Verifying

```bash
pip install ccs-verifier==1.3.0
python3 -c "
import json
from ccs_verifier.ccs_verifier_l1 import L1Receipt
with open('vectors/v1.1.20/reference-signed-001.json') as f:
    vec = json.load(f)
receipt = L1Receipt.from_dict(vec['receipt'])
print('signature valid:', receipt.verify_signature())
print('verdict:', receipt.verdict)
print('issuer:', receipt.issuer)
"
```

## Cross-Implementation Notes

- Receipts use **JCS canonical JSON** (RFC 8785) before signing.
- Signatures are **Ed25519** (RFC 8032), detached over the canonical receipt bytes.
- Base64 fields use standard alphabet with padding.
- The `signature` field is excluded from the signed payload.

## Contributing

If you are building an independent CCS implementation and find a discrepancy, please open an issue with your vector and expected result.
