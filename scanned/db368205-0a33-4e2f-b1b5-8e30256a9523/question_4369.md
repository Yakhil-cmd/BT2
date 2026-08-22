# Q4369: safeurl/allowlist bypass - AddAuthTokenHeader in http_client.go

## Question
Is there an input to `AddAuthTokenHeader` in [api/http_client.go](api/http_client.go#L152) that reaches an outbound request without passing the safeurl/allowlist validation applied elsewhere in the same flow?

## Target
- File/function: [api/http_client.go:152](api/http_client.go#L152) - `AddAuthTokenHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Find a code path (retry, redirect, pagination, asset download) that constructs its own request.
- Invariant to test: Every outbound request funnels through the same validated client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting all request constructions in the flow use the guarded transport.
