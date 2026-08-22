# Q2781: tenant/subdomain matching - newSSHCmd in ssh.go

## Question
Does `newSSHCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L49) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:49](pkg/cmd/codespace/ssh.go#L49) - `newSSHCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
