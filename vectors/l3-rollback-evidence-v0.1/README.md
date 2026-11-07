# l3-rollback-evidence-v0.1 — linked rollback-evidence receipt extension

First slice of the L3-R extension type (`ccs.rollback-evidence/0.1`): a linked
evidence receipt that attests the rollback of a settled execution, bound to the
target receipt by recomputed digest (not by claim), and fail-closed on
"executed rollback without a transaction reference".

Three deterministic cases (same key derivation and JCS/Ed25519 conventions as
the v1.4.0 corpus; separate nonce space):

- `01-rollback-valid` — valid: signature ok, target binding recomputes, tx ref present.
- `02-rollback-unbound` — MUST-FAIL: target_receipt_ref names different bytes.
- `03-rollback-no-tx-ref` — MUST-FAIL (fail-closed): executed rollback claim with no rollback_tx_ref.

Verify: `python checkers/independent_checker.py vectors/l3-rollback-evidence-v0.1/`

Design notes: `fusion/ccs-扩展设计-回滚证据与归因标签-20261107` (internal).
CC0 for vectors. Test-only key — not a production trust anchor.
