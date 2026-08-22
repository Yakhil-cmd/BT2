# Q4171: client reuse leaks headers across hosts - getTunnelManager in connection.go

## Question
Does `getTunnelManager` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L131) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [internal/codespaces/connection/connection.go:131](internal/codespaces/connection/connection.go#L131) - `getTunnelManager`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
