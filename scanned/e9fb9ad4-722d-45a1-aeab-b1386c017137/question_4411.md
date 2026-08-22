# Q4411: safeurl/allowlist bypass - printHeaders in api.go

## Question
Is there an input to `printHeaders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L613) that reaches an outbound request without passing the safeurl/allowlist validation applied elsewhere in the same flow?

## Target
- File/function: [pkg/cmd/api/api.go:613](pkg/cmd/api/api.go#L613) - `printHeaders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Find a code path (retry, redirect, pagination, asset download) that constructs its own request.
- Invariant to test: Every outbound request funnels through the same validated client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting all request constructions in the flow use the guarded transport.
