# MF-S06 — Integrity: nonce replay (same nonce already observed in this trace)

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Integrity
- **Dimensions violated**: Integrity
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The envelope nonce already appears in prior_observed_nonces_in_trace. The Integrity dimension must reject the replay rather than admitting a second call bound to the same evidence.

## Detection guidance

Track (caller, nonce) within a trace and reject duplicates. A replayed nonce indicates a duplicated or replayed request, defeating idempotency and exactly-once receipt semantics.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
