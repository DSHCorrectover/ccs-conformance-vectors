# MF-S04 — Cost: requested token budget exceeds per-call and per-trace cost limits

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Cost
- **Dimensions violated**: Cost
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The call asks for 10x the per-call token ceiling and, combined with $46.00 already spent, exceeds the $50 trace ceiling. A verifier that admits it guarantees a cost-policy violation.

## Detection guidance

Static admission must compare the declared/estimated resource request against the per-call and remaining per-trace cost budgets. Here max_tokens=2,000,000 and an estimated $18.50 breach the $5/call limit, and the remaining trace budget is $4.00.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
