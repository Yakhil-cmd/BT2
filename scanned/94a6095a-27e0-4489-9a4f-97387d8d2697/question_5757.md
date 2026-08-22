# Q5757: env-provided token used against a foreign host - HeaderHasMinimumScopes in oauth_scopes.go

## Question
Does `HeaderHasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L81) apply a GH_TOKEN/GITHUB_TOKEN environment credential to requests whose host was derived from attacker-published repository metadata?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:81](pkg/cmd/auth/shared/oauth_scopes.go#L81) - `HeaderHasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose remote points at an attacker host and let a CI job running gh with GH_TOKEN operate in it.
- Invariant to test: Environment tokens are bound to the configured default host only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with GH_TOKEN set and a foreign-host request asserting no Authorization header.
