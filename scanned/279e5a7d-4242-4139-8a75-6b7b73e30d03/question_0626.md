# Q0626: missing timeout enables hang - (API).StopCodespace in api.go

## Question
Does the request path in `StopCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L619) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [internal/codespaces/api/api.go:619](internal/codespaces/api/api.go#L619) - `(API).StopCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
