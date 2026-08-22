# Q1447: scope/permission check bypass - (AuthConfig).SetActiveToken in config.go

## Question
Does `SetActiveToken` in [internal/config/config.go](internal/config/config.go#L291) make a security decision from a scope/permission value returned by the server (or absent header) that a hostname, OAuth/device response, or git credential-protocol input the attacker supplies can influence?

## Target
- File/function: [internal/config/config.go:291](internal/config/config.go#L291) - `(AuthConfig).SetActiveToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
