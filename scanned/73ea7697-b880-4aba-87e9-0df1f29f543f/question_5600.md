# Q5600: codespace token scope reuse - (CodespacesPortForwarder).ForwardPort in port_forwarder.go

## Question
Can the per-codespace token obtained in `ForwardPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L104) be sent to a host or endpoint derived from the response rather than the tunnel's validated endpoint?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:104](internal/codespaces/portforwarder/port_forwarder.go#L104) - `(CodespacesPortForwarder).ForwardPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return connection metadata pointing at a collector.
- Invariant to test: Session tokens go only to the validated tunnel endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token's destination host.
