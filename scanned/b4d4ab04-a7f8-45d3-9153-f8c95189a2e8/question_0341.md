# Q0341: tenant/subdomain matching - buildInstallPlans in install.go

## Question
Does `buildInstallPlans` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L993) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/skills/install/install.go:993](pkg/cmd/skills/install/install.go#L993) - `buildInstallPlans`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
