# MF-S08 — Security: SSRF fetch of the cloud instance metadata service

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Security
- **Dimensions violated**: Security
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The target is the documented cloud metadata address. A successful fetch returns instance role credentials; this is the canonical SSRF target and must be blocked pre-admission.

## Detection guidance

Block requests whose host (after URL canonicalization) resolves to link-local metadata addresses, loopback, or RFC1918 control planes. The 169.254.169.254 endpoint hands temporary cloud credentials to any process that can reach it.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
