# Q2743: missing timeout enables hang - getTunnelManager in connection.go

## Question
Does the request path in `getTunnelManager` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L131) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [internal/codespaces/connection/connection.go:131](internal/codespaces/connection/connection.go#L131) - `getTunnelManager`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
