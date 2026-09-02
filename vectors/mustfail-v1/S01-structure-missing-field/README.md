# MF-S01 — Structure: envelope missing required field tool_call_id

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Structure
- **Dimensions violated**: Structure
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The envelope is not parseable as a well-formed CCS tool-call request (tool_call_id is mandatory for receipt binding and nonce tracking). There is no safe interpretation of a half-structured call.

## Detection guidance

Reject any tool-call envelope that does not contain every required structural field. A verifier that admits a malformed envelope cannot attribute, deduplicate or correlate the call; fail closed.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
