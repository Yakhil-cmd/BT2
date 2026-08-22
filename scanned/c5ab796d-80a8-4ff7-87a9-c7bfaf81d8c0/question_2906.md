# Q2906: token in process argv - NewCmdLogout in logout.go

## Question
Does `NewCmdLogout` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L24) ever place the token on a command line (git, ssh, helper) where it is visible to any local process listing during an attacker-triggered operation?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:24](pkg/cmd/auth/logout/logout.go#L24) - `NewCmdLogout`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Observe argv while the victim runs the attacker-triggered flow.
- Invariant to test: Credentials are passed over stdin or env to trusted children only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Stub-runner test asserting no argv element contains the token.
