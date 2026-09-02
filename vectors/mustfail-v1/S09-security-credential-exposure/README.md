# MF-S09 — Security: credential material embedded in an outbound git URL

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Security
- **Dimensions violated**: Security
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

The command places credential material in a URL destined for a non-allowlisted external host. Even with fake values the pattern is unsafe: real secrets in this position are disclosed to the remote host and every log along the way.

## Detection guidance

Scan arguments for credential-shaped material (access-key ids, secret keys, bearer tokens) crossing a trust boundary, including credentials embedded in URLs where they leak into logs, process tables and remote hosts. The AKID/secret pair here are the well-known AWS documentation example values; the pattern is what must be blocked.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
