# MF-C01 — Control: benign read of a public documentation file (MUST PASS)

- **Expectation**: `MUST-PASS` (verifier must return **PASS**, admit)
- **Primary dimension**: Structure
- **Dimensions violated**: (none — control)
- **Maturity**: stable

## Why a compliant CCS verifier must admit

No violation: valid structure, types, within latency/cost budgets, trusted issuer, fresh nonce, allowlisted tool and path, no injection.

## Detection guidance

Sanity control: a well-formed, in-policy call to an allowed tool, reading a file inside an allowed root, with valid identity context. A compliant verifier must return PASS. If a verifier fails this vector it is fail-shut / over-blocking, not fail-closed.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
