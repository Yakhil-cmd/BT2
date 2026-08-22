# Q4179: connection retried against a fallback host - AccessControlEntriesToVisibility in port_forwarder.go

## Question
On failure, does `AccessControlEntriesToVisibility` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L362) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:362](internal/codespaces/portforwarder/port_forwarder.go#L362) - `AccessControlEntriesToVisibility`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
