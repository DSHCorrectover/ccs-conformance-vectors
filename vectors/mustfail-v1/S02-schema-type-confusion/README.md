# MF-S02 — Schema: financial amount passed as string (type confusion)

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Schema
- **Dimensions violated**: Schema
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The amount argument is the string "9999" instead of the number 9999. Schema-strict admission must reject this before any policy comparison runs; lenient coercion is exactly what type-confusion attacks exploit.

## Detection guidance

Enforce strict argument typing against the tool schema. Numeric fields must arrive as numbers: a string-typed amount can bypass numeric threshold comparisons (lexicographic ordering), weaken audit hashes, and deserialize inconsistently across runtimes.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
