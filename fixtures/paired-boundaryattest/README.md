# Paired fixture: BoundaryAttest × CCS

One shared, format-neutral decision event; two native receipts; two independent
keys; zero shared signing/verification code. This is the paired-fixture
interoperability exercise agreed in
[issue #1](https://github.com/DSHCorrectover/ccs-conformance-vectors/issues/1)
between [BoundaryAttest](https://github.com/cullenmeyers/BoundaryAttest) and CCS.

## The rule (both sides)

- We read the **same** `event.json`; neither side canonicalizes that file for
  the other. Each side computes its own digests under its own canonicalization.
- BoundaryAttest signs with its own envelope + stableJson + its own key custody
  and is verified only by the BoundaryAttest verifier.
- CCS signs with its own receipt schema + JCS (RFC 8785) + its own key and is
  verified only by the CCS verifier.
- Neither implementation imports the other's code.
- Mismatches are **deliverables**: where similarly-named fields bind
  differently, we document it in `NOTES.md` rather than forcing compatibility.

## Layout

```
paired-boundaryattest/
  event.json                  # neutral shared event (read-only input to both sides)
  01-deny/
    ccs-side/                 # CCS-native artifacts
      build_ccs_receipt.py    # reads ../../event.json, emits CCS L1 receipt
      verify_ccs_receipt.py   # independent re-verification (imports no build code)
      receipt.json
      signing-input.jcs
      signature.sig
      public-key.b64
      tool-args.json
      response-body.json
      expected.json
    boundaryattest-side/      # BoundaryAttest-native artifacts (owner: @cullenmeyers)
      README.md               # what to drop here
    crosswalk.py              # field-level PASS / MISMATCH / N/A / PENDING harness
    crosswalk.json            # generated
    NOTES.md                  # documented semantic mismatches & scope differences
```

## Fixture 01: DENY (pre-admission)

A consequential request (`shell.exec` appending to `/etc/passwd`) is evaluated
against a named/versioned policy (`policy:system-path-write` v1.4.0). The gate
returns **DENY before execution**; no command runs; decision evidence is
exported. A future fixture 02 will cover ALLOW with execution-result semantics.

## Reproduce

```bash
# CCS side
cd 01-deny/ccs-side
python3 build_ccs_receipt.py
python3 verify_ccs_receipt.py      # 22/22 checks

# Crosswalk (PENDING until the BoundaryAttest receipt lands)
cd ..
python3 crosswalk.py
```

The CCS fixture key is derived deterministically from a fixed, published seed
(`build_ccs_receipt.py`, `FIXTURE_SEED`) and is **fixture-only**; it must never
be reused outside this directory.

## Status

- [x] Neutral `event.json` + event spec
- [x] CCS-native receipt + independent verifier (22/22 checks)
- [x] Crosswalk harness (12 semantic rows)
- [ ] BoundaryAttest-native receipt (waiting on @cullenmeyers, per issue #1)
- [ ] Crosswalk run with both receipts; NOTES.md finalized
