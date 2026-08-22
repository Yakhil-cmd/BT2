# Q4405: account/host switch persists wrong credentials - (remoteResolver).Resolver in remote_resolver.go

## Question
Can `Resolver` in [pkg/cmd/factory/remote_resolver.go](pkg/cmd/factory/remote_resolver.go#L28) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [pkg/cmd/factory/remote_resolver.go:28](pkg/cmd/factory/remote_resolver.go#L28) - `(remoteResolver).Resolver`
- Entrypoint: gh factory remote
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
