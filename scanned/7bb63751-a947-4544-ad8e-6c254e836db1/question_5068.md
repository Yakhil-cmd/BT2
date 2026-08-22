# Q5068: zip slip - GetScopes in oauth_scopes.go

## Question
Does `GetScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L36) trust the archive member name when extracting, so an entry named `../../.config/gh/hosts.yml` (or an absolute/UNC name) is written outside the destination?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:36](pkg/cmd/auth/shared/oauth_scopes.go#L36) - `GetScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a workflow artifact / skill / extension archive containing a traversal entry, then let the victim run gh auth.
- Invariant to test: Extraction resolves each member against the destination and rejects anything escaping it.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over crafted zips (`../`, `/etc/x`, `C:\`, `\\host\share`, backslash separators) asserting extraction fails.
