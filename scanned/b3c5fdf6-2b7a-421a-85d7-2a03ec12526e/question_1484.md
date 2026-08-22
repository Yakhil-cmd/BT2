# Q1484: token in process argv - NewCmdSwitch in switch.go

## Question
Does `NewCmdSwitch` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L24) ever place the token on a command line (git, ssh, helper) where it is visible to any local process listing during an attacker-triggered operation?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:24](pkg/cmd/auth/switch/switch.go#L24) - `NewCmdSwitch`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Observe argv while the victim runs the attacker-triggered flow.
- Invariant to test: Credentials are passed over stdin or env to trusted children only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Stub-runner test asserting no argv element contains the token.
