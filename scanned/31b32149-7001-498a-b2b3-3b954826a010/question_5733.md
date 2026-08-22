# Q5733: hosts.yml poisoned via login flow - promptForHostname in login.go

## Question
Can an unprivileged attacker who controls the server the victim authenticates against drive `promptForHostname` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L247) to add or modify an entry in the victim's hosts configuration for a host they did not intend to trust?

## Target
- File/function: [pkg/cmd/auth/login/login.go:247](pkg/cmd/auth/login/login.go#L247) - `promptForHostname`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Run a GHES-looking endpoint, get the victim to authenticate once, and have the response steer the stored host/user keys.
- Invariant to test: Stored credential keys derive from the URL the user typed, never from server-returned identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test a login against a server returning a mismatched login/host, asserting the config key equals the dialed host.
