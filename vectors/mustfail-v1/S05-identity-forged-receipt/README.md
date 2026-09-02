# MF-S05 — Identity: receipt offered with untrusted issuer and algorithm 'none'

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Identity
- **Dimensions violated**: Identity
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The caller offers a receipt from an issuer not in trusted_issuers, claims signing_algorithm 'none', and carries an empty signature. Accepting it would destroy the Identity dimension's trust anchor.

## Detection guidance

Every admitted call must bind to a receipt signed by a trusted issuer using a trusted algorithm. Reject self-asserted issuers, unknown key fingerprints, and unsigned/algorithm-none receipts.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
