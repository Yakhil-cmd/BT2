# Q5592: connection retried against a fallback host - waitUntilCodespaceConnectionReady in codespaces.go

## Question
On failure, does `waitUntilCodespaceConnectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L78) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/codespaces.go:78](internal/codespaces/codespaces.go#L78) - `waitUntilCodespaceConnectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
