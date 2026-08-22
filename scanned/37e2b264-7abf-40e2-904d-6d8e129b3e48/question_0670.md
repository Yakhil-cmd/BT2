# Q0670: account/host switch persists wrong credentials - (capiTransport).RoundTrip in client.go

## Question
Can `RoundTrip` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L64) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:64](pkg/cmd/agent-task/capi/client.go#L64) - `(capiTransport).RoundTrip`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
