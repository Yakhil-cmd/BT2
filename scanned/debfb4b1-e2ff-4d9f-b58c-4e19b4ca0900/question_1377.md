# Q1377: connection retried against a fallback host - chooseCodespaceFromList in common.go

## Question
On failure, does `chooseCodespaceFromList` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L93) retry the connection against a host from the error/response payload?

## Target
- File/function: [pkg/cmd/codespace/common.go:93](pkg/cmd/codespace/common.go#L93) - `chooseCodespaceFromList`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
