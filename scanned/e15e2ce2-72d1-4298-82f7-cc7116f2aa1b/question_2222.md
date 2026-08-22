# Q2222: tenant/subdomain matching - clientOptions in client.go

## Question
Does `clientOptions` in [api/client.go](api/client.go#L256) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [api/client.go:256](api/client.go#L256) - `clientOptions`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
