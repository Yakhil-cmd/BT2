# Q5761: account/host switch persists wrong credentials - clientOptions in client.go

## Question
Can `clientOptions` in [api/client.go](api/client.go#L256) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [api/client.go:256](api/client.go#L256) - `clientOptions`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
