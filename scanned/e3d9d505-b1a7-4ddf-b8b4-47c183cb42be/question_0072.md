# Q0072: token for host A returned for host B - HasMinimumScopes in oauth_scopes.go

## Question
Does `HasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L70) resolve the active token by falling back across hosts or accounts when the requested host has no entry?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:70](pkg/cmd/auth/shared/oauth_scopes.go#L70) - `HasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Point gh at an attacker host with no stored entry and see whether the github.com token is returned.
- Invariant to test: Token lookup is exact-match on host; a miss returns empty.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test asserting a miss returns no token and no fallback.
