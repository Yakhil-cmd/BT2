# Q4396: attacker text written into git config - remotesFunc in default.go

## Question
Can a repo/remote/host string or API response field the attacker publishes flowing through `remotesFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L178) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/factory/default.go:178](pkg/cmd/factory/default.go#L178) - `remotesFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
