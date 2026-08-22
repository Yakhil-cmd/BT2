# Q4498: tenant/subdomain matching - cloneRun in clone.go

## Question
Does `cloneRun` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L75) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:75](pkg/cmd/gist/clone/clone.go#L75) - `cloneRun`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
