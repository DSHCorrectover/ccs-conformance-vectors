# MF-S10 — Security: tool absent from role grants and global allowlist

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Security
- **Dimensions violated**: Security
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

admin.emergency_revoke_all_sessions appears nowhere in tool_allowlist and customer_support has no administrative grants. The call is a privilege boundary violation and must fail closed.

## Detection guidance

Authorize every call against both the global tool allowlist and the caller role's grants. Unknown/ungranted tools must be denied regardless of argument content; social-engineering 'reason' fields do not grant privilege.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
