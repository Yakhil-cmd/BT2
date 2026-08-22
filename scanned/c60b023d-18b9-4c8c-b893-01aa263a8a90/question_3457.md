# Q3457: host-scoped client leaked into another flow - getTunnelManager in connection.go

## Question
Can the client/transport constructed in `getTunnelManager` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L131) (with its auth round-tripper) be reused by a later flow whose target host came from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/connection/connection.go:131](internal/codespaces/connection/connection.go#L131) - `getTunnelManager`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
