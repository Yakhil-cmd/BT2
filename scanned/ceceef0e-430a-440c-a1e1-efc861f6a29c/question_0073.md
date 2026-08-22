# Q0073: scope/permission check bypass - HeaderHasMinimumScopes in oauth_scopes.go

## Question
Does `HeaderHasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L81) make a security decision from a scope/permission value returned by the server (or absent header) that a hostname, OAuth/device response, or git credential-protocol input the attacker supplies can influence?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:81](pkg/cmd/auth/shared/oauth_scopes.go#L81) - `HeaderHasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
