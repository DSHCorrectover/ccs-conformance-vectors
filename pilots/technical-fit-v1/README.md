# technical-fit-v1 — IICP x CCS technical-fit experiment fixtures

Six deterministic cases (C1-C6) for the IICP x CCS interop pilot (see Roble Mumin thread, Dec 2026 window).

- fixtures/case-C{1..4}-receipt.json : allow/block decisions, signed (Ed25519 over JCS/RFC 8785 canonical bytes)
- fixtures/case-C5-tampered-receipt.json : MUST-FAIL (payload tampered, signature unchanged)
- fixtures/case-C6-replay-copy.json : byte-identical copy of C1 (replay detection case)
- verify_pilot.py : offline verifier (stdlib + cryptography)
- pilot-public-key.pub.pem : pilot signing key (separate from the 2026-10 evidence trust root)

Verify: python verify_pilot.py fixtures/case-C1-receipt.json
CC0 for vectors. Test-only key — not a production trust anchor.

## Classification note (2026-11-05)

This is a **pilot fixture set** with its own offline verifier (`verify_pilot.py`): C1–C4/C6 signatures VALID, C5 tampered copy INVALID by design. It is intentionally **not** part of the `independent_checker.py` population — its receipt envelope (embedded `signature_hex`) differs from the checker's case model (`receipt*.json` + `expected.json`). The manifest pins the closed inventory; run `python verify_pilot.py fixtures/case-C1-receipt.json` to verify (exit 0 = valid, 1 = tamper detected).
