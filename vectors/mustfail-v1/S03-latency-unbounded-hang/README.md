# MF-S03 — Latency: long-running tool call admitted with no deadline (hang)

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Latency
- **Dimensions violated**: Latency
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

tail -f never returns. The envelope explicitly carries no timeout and no deadline, so the Latency dimension cannot bound the call. Admission without a deadline is a fail-closed condition.

## Detection guidance

Calls to unbounded/streaming tools must carry an explicit deadline that fits the trace latency budget (deadline_us here). A call with no timeout can hang the agent loop indefinitely, pinning budget and stalling the trace; fail closed when the deadline is absent or exceeds the budget.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
