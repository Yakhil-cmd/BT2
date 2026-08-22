# Q0785: insecure storage migration - GetScopes in oauth_scopes.go

## Question
Can the config migration performed by `GetScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L36) be triggered on attacker-influenced input so credentials are rewritten to a new location with weaker permissions or duplicated under a wrong host key?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:36](pkg/cmd/auth/shared/oauth_scopes.go#L36) - `GetScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Craft the pre-migration state through a normal gh flow against an attacker host.
- Invariant to test: Migration preserves host binding and 0600 permissions, and is idempotent.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test migrating a hostile config asserting keys and modes.
