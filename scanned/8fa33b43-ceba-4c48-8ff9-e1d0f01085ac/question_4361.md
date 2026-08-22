# Q4361: error retry re-sends credentials elsewhere - handleResponse in client.go

## Question
On failure, does `handleResponse` in [api/client.go](api/client.go#L159) retry against a different host/endpoint (fallback API, mirror) while keeping the Authorization header?

## Target
- File/function: [api/client.go:159](api/client.go#L159) - `handleResponse`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Fail the primary request from an attacker-influenced endpoint to trigger the fallback.
- Invariant to test: Fallbacks are host-pinned or unauthenticated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry target host and headers.
