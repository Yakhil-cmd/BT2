# Q2189: plaintext fallback for token storage - NewCmdLogin in login.go

## Question
Does `NewCmdLogin` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L45) silently fall back from the OS keyring to a plaintext config file when an attacker-triggerable error occurs?

## Target
- File/function: [pkg/cmd/auth/login/login.go:45](pkg/cmd/auth/login/login.go#L45) - `NewCmdLogin`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Cause the keyring path to fail during an attacker-initiated flow, leaving the token on disk.
- Invariant to test: Storage downgrade is explicit, user-visible, and file-permission protected.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test injecting a keyring error and asserting either failure or a 0600 file plus a warning.
