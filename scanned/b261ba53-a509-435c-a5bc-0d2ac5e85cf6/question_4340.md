# Q4340: tenant/subdomain matching - NewCmdSwitch in switch.go

## Question
Does `NewCmdSwitch` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L24) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:24](pkg/cmd/auth/switch/switch.go#L24) - `NewCmdSwitch`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
