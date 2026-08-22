# Q3512: connection retried against a fallback host - getPortPairs in ports.go

## Question
On failure, does `getPortPairs` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L372) retry the connection against a host from the error/response payload?

## Target
- File/function: [pkg/cmd/codespace/ports.go:372](pkg/cmd/codespace/ports.go#L372) - `getPortPairs`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
