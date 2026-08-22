# Q5810: account/host switch persists wrong credentials - (Client).Clone in client.go

## Question
Can `Clone` in [git/client.go](git/client.go#L908) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [git/client.go:908](git/client.go#L908) - `(Client).Clone`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
