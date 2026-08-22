# Q5049: attacker text written into git config - NewCmdRefresh in refresh.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies flowing through `NewCmdRefresh` in [pkg/cmd/auth/refresh/refresh.go](pkg/cmd/auth/refresh/refresh.go#L43) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/auth/refresh/refresh.go:43](pkg/cmd/auth/refresh/refresh.go#L43) - `NewCmdRefresh`
- Entrypoint: gh auth refresh
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
