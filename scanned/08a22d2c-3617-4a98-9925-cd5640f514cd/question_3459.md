# Q3459: connection retried against a fallback host - (CodespacesPortForwarder).ForwardPortToListener in port_forwarder.go

## Question
On failure, does `ForwardPortToListener` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L63) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:63](internal/codespaces/portforwarder/port_forwarder.go#L63) - `(CodespacesPortForwarder).ForwardPortToListener`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
