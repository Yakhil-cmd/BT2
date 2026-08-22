# Q1306: connection retried against a fallback host - newSCPCommand in ssh.go

## Question
On failure, does `newSCPCommand` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L107) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/ssh.go:107](internal/codespaces/ssh.go#L107) - `newSCPCommand`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
