# Q0845: error retry re-sends credentials elsewhere - (paginatedArrayReader).Read in pagination.go

## Question
On failure, does `Read` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L123) retry against a different host/endpoint (fallback API, mirror) while keeping the Authorization header?

## Target
- File/function: [pkg/cmd/api/pagination.go:123](pkg/cmd/api/pagination.go#L123) - `(paginatedArrayReader).Read`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Fail the primary request from an attacker-influenced endpoint to trigger the fallback.
- Invariant to test: Fallbacks are host-pinned or unauthenticated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry target host and headers.
