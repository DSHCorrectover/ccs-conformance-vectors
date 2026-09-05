# BoundaryAttest side (owner: @cullenmeyers)

Drop the BoundaryAttest-native receipt for `../../event.json` here.

Expected files (names are suggestions; if your tooling uses different names,
keep them and note the mapping in this README):

- `receipt.json` — the BoundaryAttest-native envelope/claim for the event
- `signature` — the native signature (format per BoundaryAttest v0.1)
- `public-key` — the native public key or key reference
- a short note of how an independent party verifies it (verifier name/version,
  or a script you provide)

Per the agreement in issue #1:

- sign with your own key, native envelope, stableJson canonicalization, native
  verifier — no CCS signing/verifier code anywhere in this directory;
- `policy_ref`, `policy_version`, `policy_digest` (the digest is in
  `event.json` under `policy.policy_digest`, sha256 over the exact policy text)
  go in as adapter-specific signed claim fields inside `claim`, keeping
  BoundaryAttest Interop Profile v0.1 core unchanged;
- the event is pre-admission DENY and nothing was executed — verdict DENY,
  no execution-result/side-effect semantics yet (those come in fixture 02).

Once `receipt.json` lands, re-running `../crosswalk.py` will pick it up
automatically and flip the PENDING rows to PASS / MISMATCH / N/A.
