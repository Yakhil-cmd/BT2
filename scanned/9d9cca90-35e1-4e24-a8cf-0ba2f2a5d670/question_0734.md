# Q0734: hosts.yml poisoned via login flow - (AuthConfig).TokenFromKeyring in config.go

## Question
Can an unprivileged attacker who controls the server the victim authenticates against drive `TokenFromKeyring` in [internal/config/config.go](internal/config/config.go#L299) to add or modify an entry in the victim's hosts configuration for a host they did not intend to trust?

## Target
- File/function: [internal/config/config.go:299](internal/config/config.go#L299) - `(AuthConfig).TokenFromKeyring`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Run a GHES-looking endpoint, get the victim to authenticate once, and have the response steer the stored host/user keys.
- Invariant to test: Stored credential keys derive from the URL the user typed, never from server-returned identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test a login against a server returning a mismatched login/host, asserting the config key equals the dialed host.
