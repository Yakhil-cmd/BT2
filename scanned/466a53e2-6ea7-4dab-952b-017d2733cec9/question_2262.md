# Q2262: safeurl/allowlist bypass - extensionManager in default.go

## Question
Is there an input to `extensionManager` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L272) that reaches an outbound request without passing the safeurl/allowlist validation applied elsewhere in the same flow?

## Target
- File/function: [pkg/cmd/factory/default.go:272](pkg/cmd/factory/default.go#L272) - `extensionManager`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Find a code path (retry, redirect, pagination, asset download) that constructs its own request.
- Invariant to test: Every outbound request funnels through the same validated client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting all request constructions in the flow use the guarded transport.
