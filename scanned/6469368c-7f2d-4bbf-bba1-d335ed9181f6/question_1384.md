# Q1384: OAuth callback/state validation - (capiTransport).RoundTrip in client.go

## Question
Does the browser/device flow driven by `RoundTrip` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L64) accept a callback or device response without binding state, PKCE, or the originating host?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:64](pkg/cmd/agent-task/capi/client.go#L64) - `(capiTransport).RoundTrip`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Feed the local callback listener a forged request so gh stores an attacker-issued token for the victim's host.
- Invariant to test: Callbacks are accepted only with a matching state and from the flow gh initiated.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test posting a forged callback with a wrong state and asserting rejection.
