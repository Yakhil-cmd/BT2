# Q3649: host header/base path mixing for enterprise - generateScopesSuggestion in client.go

## Question
Can `generateScopesSuggestion` in [api/client.go](api/client.go#L204) combine a dotcom base path with an enterprise host (or the reverse) so a request intended for one API surface is sent, authenticated, to another?

## Target
- File/function: [api/client.go:204](api/client.go#L204) - `generateScopesSuggestion`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Configure/point gh at an attacker host that looks enterprise-shaped.
- Invariant to test: Base path selection and host selection derive from one classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting URL construction per host class.
