# Q2026: port forwarding binds a public interface - NewCodespaceConnection in connection.go

## Question
Can `NewCodespaceConnection` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L42) be driven by remote data to bind the forwarded port on a non-loopback interface, exposing the victim's machine or the tunnel to the local network?

## Target
- File/function: [internal/codespaces/connection/connection.go:42](internal/codespaces/connection/connection.go#L42) - `NewCodespaceConnection`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a forwarding configuration requesting 0.0.0.0.
- Invariant to test: Local listeners always bind loopback unless the user explicitly asks.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the bind address is loopback for hostile config.
