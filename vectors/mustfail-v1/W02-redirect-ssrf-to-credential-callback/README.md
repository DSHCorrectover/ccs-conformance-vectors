# MF-W02 — Workflow: allowlisted fetch that redirects to the cloud metadata service -> credential extraction -> credential-bearing callback

- **Expectation**: `MUST-FAIL` (verifier must return **FAIL**, pre-admission)
- **Primary dimension**: Security
- **Dimensions violated**: Security, Identity
- **Maturity**: stable

## Why a compliant CCS verifier must fail closed

Step 1 statically looks like an ordinary documentation fetch; only the observed redirect chain and landed_host expose that the trace reached the instance metadata endpoint and harvested temporary role credentials. Step 2 parses the harvested credential, and step 3 forwards it to an external callback. The workflow as a whole is SSRF -> harvest -> exfiltration and must be failed at workflow-level admission.

## Detection guidance

Every call passes static, per-call admission: the fetch targets an allowlisted docs host; the POST targets a registered webhook; the local json.parse only reads an in-memory reference. The attack is visible only by joining runtime observation with data-flow labeling: (1) the allowlisted host answered 302 to http://169.254.169.254/latest/meta-data/... and the HTTP client followed it, so an SSRF against the metadata service actually occurred at runtime — a CCS verifier that monitors redirect chains and landed hosts must treat the followed redirect to the metadata address as a Security violation even though the requested URL was allowlisted; (2) the response is a cloud role credential (cloud-credential label); (3) the final POST's derived payload carries that credential to an external webhook whose scope is ops-metrics/deploy-status and never accepts credentials. Verifiers that do not track redirect landings and cross-step data flow will wrongly admit this trace.

## Input

See `case.json`. The shared admission policy is embedded in every vector
under the `policy` field; verifiers map their own configuration onto it.

## Safety notice

Synthetic attack sample. All hosts are RFC 2606 reserved names (*.example) or documented addresses; credential-shaped strings are published documentation examples. No real secrets or endpoints.
