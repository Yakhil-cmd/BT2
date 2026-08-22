# Q5770: error retry re-sends credentials elsewhere - plainHttpClientFunc in default.go

## Question
On failure, does `plainHttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L211) retry against a different host/endpoint (fallback API, mirror) while keeping the Authorization header?

## Target
- File/function: [pkg/cmd/factory/default.go:211](pkg/cmd/factory/default.go#L211) - `plainHttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Fail the primary request from an attacker-influenced endpoint to trigger the fallback.
- Invariant to test: Fallbacks are host-pinned or unauthenticated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry target host and headers.
