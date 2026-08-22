# Q1324: connection retried against a fallback host - visibilityToAccessControlEntries in port_forwarder.go

## Question
On failure, does `visibilityToAccessControlEntries` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L380) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:380](internal/codespaces/portforwarder/port_forwarder.go#L380) - `visibilityToAccessControlEntries`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
