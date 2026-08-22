# Q2935: TLS verification weakened on a branch - generateScopesSuggestion in client.go

## Question
Is there a code path through `generateScopesSuggestion` in [api/client.go](api/client.go#L204) where a custom transport, test hook, or insecure flag disables certificate verification in a build users actually run?

## Target
- File/function: [api/client.go:204](api/client.go#L204) - `generateScopesSuggestion`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Reach the branch via normal flags/env in a release build.
- Invariant to test: TLS verification is never disabled in non-test code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the production transport has no InsecureSkipVerify.
