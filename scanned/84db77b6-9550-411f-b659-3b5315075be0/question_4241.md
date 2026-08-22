# Q4241: tenant/subdomain matching - CapiClientFunc in capi.go

## Question
Does `CapiClientFunc` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L21) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:21](pkg/cmd/agent-task/shared/capi.go#L21) - `CapiClientFunc`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
