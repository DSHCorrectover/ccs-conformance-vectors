# technical-fit-v1 — IICP x CCS technical-fit experiment fixtures

Six deterministic cases (C1-C6) for the IICP x CCS interop pilot (see Roble Mumin thread, Dec 2026 window).

- fixtures/case-C{1..4}-receipt.json : allow/block decisions, signed (Ed25519 over JCS/RFC 8785 canonical bytes)
- fixtures/case-C5-tampered-receipt.json : MUST-FAIL. Exact tamper: a **two-byte insertion** `-X` into `payload.args.path` (`/data/quarterly.csv` → `/data/quarterly-X.csv`); the Ed25519 signature is byte-identical to C1's and therefore no longer covers the modified payload. (Earlier descriptions saying "one-byte flip" were wrong; corrected 2026-11-07 after external review by R. La Touche.)
- fixtures/case-C6-replay-copy.json : canonical-payload-identical copy of C1 (envelope-only note, outside the signed bytes; replay detection happens at the correlation layer, so signature verification exits 0 by design — the batch verifier flags it as a replay candidate)
- verify_pilot.py : offline batch verifier (stdlib + cryptography)
- pilot-public-key.pub.pem : pilot signing key (separate from the 2026-10 evidence trust root)

Verify (batch — inventory + contract + replay scan):

```
python verify_pilot.py
```

Single receipt (backwards compatible): `python verify_pilot.py fixtures/case-C1-receipt.json`

CC0 for vectors. Test-only key — not a production trust anchor.

## Classification note (2026-11-05)

This is a **pilot fixture set** with its own offline verifier (`verify_pilot.py`): C1–C4/C6 signatures VALID, C5 tampered copy INVALID by design. It is intentionally **not** part of the `independent_checker.py` population — its receipt envelope (embedded `signature_hex`) differs from the checker's case model (`receipt*.json` + `expected.json`). The manifest pins the closed inventory.

## Hash-input serialization (declared 2026-11-07)

External reviewers (R. La Touche 2026-11-06; Lars/MoltyCel 2026-10) could not recompute
custody-style array hashes (e.g. `nativeCaseArraySHA256` in earlier evidence packs)
because the serialization was never stated. Standing rules for this repository:

- **Manifest digests** (`manifest.json` `files` map): SHA-256 over the **raw file bytes** as shipped.
- **`canonical_hex` in receipts**: hex encoding of **JCS (RFC 8785) canonical UTF-8 bytes** of `payload`, i.e. exactly the bytes the Ed25519 signature covers (payload minus the `signature` member). `verify_pilot.py` recomputes and compares — it does not trust the pinned hex.
- **Any hash over an array or structured object** (custody blocks, evidence packs): the serialization MUST be declared next to the hash. Default where undeclared: JCS (RFC 8785) canonical bytes of the JSON array/object. Producers must state deviations explicitly; consumers must treat an undeclared serialization as unverifiable (fail-closed).

## Timestamp semantics (declared 2026-11-07)

`decided_at` in these fixtures is an **RFC 3339 UTC string** (application-level decision
time), fixed as a string by pilot contract. This is distinct from the numeric epoch
`timestamp` member of the main conformance receipt model (draft-correctover-ccs-10);
the two must not be conflated when mapping between IICP and CCS record shapes.

## Verifier changes (2026-11-07)

`verify_pilot.py` v2 (closing external-review gaps):

- closed-inventory manifest validation, both directions (stale/unpinned files are failures);
- signatures verified over **recomputed** JCS bytes; pinned `canonical_hex` must match the recompute (canonicalizer-divergence detection);
- contract check: C1-C4/C6 must verify valid, C5 must fail — a batch where C5 "passes" fails the run;
- cross-submission duplicate (replay-candidate) scan over canonical payloads + correlation ids;
- **RFC 8785-compliant canonicalization** (ES6 `Number::toString` for numbers, UTF-16 code-unit key ordering); differentially tested against the `jcs` reference library (9,018 cases, 0 mismatches) and byte-identical to the previous `json.dumps`-based serializer on every shipped fixture;
- deterministic output (no hash-seed-dependent iteration); summary totals recomputed from the manifest, never echoed from input.
