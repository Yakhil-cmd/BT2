# Q4886: session state cached across codespaces - (CodespacesPortForwarder).ForwardPortToListener in port_forwarder.go

## Question
Can connection state or credentials cached by `ForwardPortToListener` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L63) be reused for a different codespace or owner?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:63](internal/codespaces/portforwarder/port_forwarder.go#L63) - `(CodespacesPortForwarder).ForwardPortToListener`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Connect to an attacker-shared codespace then to the victim's own.
- Invariant to test: Cached session material is keyed by codespace identity and never reused.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting cache keys include the codespace id and owner.
