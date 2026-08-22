# Q2171: account/host switch persists wrong credentials - (AuthConfig).TokenForUser in config.go

## Question
Can `TokenForUser` in [internal/config/config.go](internal/config/config.go#L502) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [internal/config/config.go:502](internal/config/config.go#L502) - `(AuthConfig).TokenForUser`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
