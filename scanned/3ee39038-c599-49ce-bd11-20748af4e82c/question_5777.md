# Q5777: account/host switch persists wrong credentials - NewCmdApi in api.go

## Question
Can `NewCmdApi` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L66) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [pkg/cmd/api/api.go:66](pkg/cmd/api/api.go#L66) - `NewCmdApi`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
