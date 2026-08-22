# Q5051: account/host switch persists wrong credentials - NewCmdToken in token.go

## Question
Can `NewCmdToken` in [pkg/cmd/auth/token/token.go](pkg/cmd/auth/token/token.go#L23) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [pkg/cmd/auth/token/token.go:23](pkg/cmd/auth/token/token.go#L23) - `NewCmdToken`
- Entrypoint: gh auth token
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
