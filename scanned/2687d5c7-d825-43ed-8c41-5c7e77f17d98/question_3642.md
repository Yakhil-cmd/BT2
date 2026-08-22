# Q3642: stored token readable by other local surfaces - HasMinimumScopes in oauth_scopes.go

## Question
Does `HasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L70) place the token somewhere reachable by processes gh itself launches for attacker-published code (extensions, skills, editors, hooks)?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:70](pkg/cmd/auth/shared/oauth_scopes.go#L70) - `HasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs, then read the credential.
- Invariant to test: Tokens live in the keyring or a 0600 file and are not exported to child processes of third-party code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment omits token variables.
