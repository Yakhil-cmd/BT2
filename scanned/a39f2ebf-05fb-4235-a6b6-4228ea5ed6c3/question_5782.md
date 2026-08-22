# Q5782: error retry re-sends credentials elsewhere - openUserFile in api.go

## Question
On failure, does `openUserFile` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L633) retry against a different host/endpoint (fallback API, mirror) while keeping the Authorization header?

## Target
- File/function: [pkg/cmd/api/api.go:633](pkg/cmd/api/api.go#L633) - `openUserFile`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Fail the primary request from an attacker-influenced endpoint to trigger the fallback.
- Invariant to test: Fallbacks are host-pinned or unauthenticated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry target host and headers.
