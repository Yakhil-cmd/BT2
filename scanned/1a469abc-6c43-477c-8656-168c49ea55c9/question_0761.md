# Q0761: attacker text written into git config - NewCmdLogin in login.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies flowing through `NewCmdLogin` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L45) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/auth/login/login.go:45](pkg/cmd/auth/login/login.go#L45) - `NewCmdLogin`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
