# Q1321: host key / SSH endpoint from the API response - (CodespacesPortForwarder).ConnectToForwardedPort in port_forwarder.go

## Question
Does `ConnectToForwardedPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L237) take the SSH destination, port, or connection parameters from a response object that an unprivileged attacker can own (their codespace, their org-less repo) and connect with the victim's credentials?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:237](internal/codespaces/portforwarder/port_forwarder.go#L237) - `(CodespacesPortForwarder).ConnectToForwardedPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish/share a codespace whose connection metadata targets an attacker host.
- Invariant to test: Connection targets are validated against the authenticated host and expected tunnel domain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the dialed endpoint for hostile metadata.
