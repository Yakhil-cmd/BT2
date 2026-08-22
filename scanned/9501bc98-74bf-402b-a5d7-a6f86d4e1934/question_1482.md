# Q1482: tenant/subdomain matching - NewCmdToken in token.go

## Question
Does `NewCmdToken` in [pkg/cmd/auth/token/token.go](pkg/cmd/auth/token/token.go#L23) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/auth/token/token.go:23](pkg/cmd/auth/token/token.go#L23) - `NewCmdToken`
- Entrypoint: gh auth token
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
