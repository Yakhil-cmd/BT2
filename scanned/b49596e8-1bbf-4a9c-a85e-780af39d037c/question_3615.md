# Q3615: account/host switch persists wrong credentials - (cfg).ActiveToken in flow.go

## Question
Can `ActiveToken` in [internal/authflow/flow.go](internal/authflow/flow.go#L122) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [internal/authflow/flow.go:122](internal/authflow/flow.go#L122) - `(cfg).ActiveToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
