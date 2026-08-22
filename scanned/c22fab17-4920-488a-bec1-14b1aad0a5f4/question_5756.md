# Q5756: username/identity spoof in status output - HasMinimumScopes in oauth_scopes.go

## Question
Can attacker-controlled server responses make `HasMinimumScopes` in [pkg/cmd/auth/shared/oauth_scopes.go](pkg/cmd/auth/shared/oauth_scopes.go#L70) display an identity or host the victim trusts while the underlying credential belongs to another host?

## Target
- File/function: [pkg/cmd/auth/shared/oauth_scopes.go:70](pkg/cmd/auth/shared/oauth_scopes.go#L70) - `HasMinimumScopes`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return a fabricated login/user object from an attacker-run GHES host.
- Invariant to test: Displayed identity is annotated with the host it was fetched from and is not used for trust.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting displayed identity carries the true host.
