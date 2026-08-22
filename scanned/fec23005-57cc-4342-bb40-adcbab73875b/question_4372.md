# Q4372: tenant/subdomain matching - Default in host.go

## Question
Does `Default` in [internal/ghinstance/host.go](internal/ghinstance/host.go#L21) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [internal/ghinstance/host.go:21](internal/ghinstance/host.go#L21) - `Default`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
