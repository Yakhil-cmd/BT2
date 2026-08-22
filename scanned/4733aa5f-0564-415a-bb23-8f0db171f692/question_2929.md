# Q2929: OAuth callback/state validation - HeaderHasMinimumScopes in oauth_scopes.go

## Question
Does the browser/device flow driven by `HeaderHasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L81) accept a callback or device response without binding state, PKCE, or the originating host?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:81](pkg/cmd/auth/shared/oauth_scopes.go#L81) - `HeaderHasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Feed the local callback listener a forged request so gh stores an attacker-issued token for the victim's host.
- Invariant to test: Callbacks are accepted only with a matching state and from the flow gh initiated.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test posting a forged callback with a wrong state and asserting rejection.
