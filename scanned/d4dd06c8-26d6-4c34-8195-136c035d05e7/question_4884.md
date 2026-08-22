# Q4884: host key / SSH endpoint from the API response - getTunnelManager in connection.go

## Question
Does `getTunnelManager` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L131) take the SSH destination, port, or connection parameters from a response object that an unprivileged attacker can own (their codespace, their org-less repo) and connect with the victim's credentials?

## Target
- File/function: [internal/codespaces/connection/connection.go:131](internal/codespaces/connection/connection.go#L131) - `getTunnelManager`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish/share a codespace whose connection metadata targets an attacker host.
- Invariant to test: Connection targets are validated against the authenticated host and expected tunnel domain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the dialed endpoint for hostile metadata.
