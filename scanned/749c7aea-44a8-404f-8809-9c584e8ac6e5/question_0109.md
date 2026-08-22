# Q0109: safeurl/allowlist bypass - TranslateRemotes in remote.go

## Question
Is there an input to `TranslateRemotes` in [context/remote.go](context/remote.go#L105) that reaches an outbound request without passing the safeurl/allowlist validation applied elsewhere in the same flow?

## Target
- File/function: [context/remote.go:105](context/remote.go#L105) - `TranslateRemotes`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Find a code path (retry, redirect, pagination, asset download) that constructs its own request.
- Invariant to test: Every outbound request funnels through the same validated client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting all request constructions in the flow use the guarded transport.
