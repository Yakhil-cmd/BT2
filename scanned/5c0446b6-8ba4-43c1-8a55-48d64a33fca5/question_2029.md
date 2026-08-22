# Q2029: unauthenticated fallback on error - getTunnelManager in connection.go

## Question
When authentication fails inside `getTunnelManager` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L131), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [internal/codespaces/connection/connection.go:131](internal/codespaces/connection/connection.go#L131) - `getTunnelManager`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
