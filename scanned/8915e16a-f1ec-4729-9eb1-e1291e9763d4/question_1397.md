# Q1397: token leaked into child env/argv - runExternalCmd in copilot.go

## Question
Does `runExternalCmd` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L213) pass the active GitHub token via argv or an inherited environment into a process whose identity is influenced by an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:213](pkg/cmd/copilot/copilot.go#L213) - `runExternalCmd`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get gh to spawn a helper for an attacker-controlled host/extension and read the token from its own environment or /proc argv.
- Invariant to test: The token is only passed to processes bound to the host it authenticates.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Assert the env/argv captured by a stub runner contains no token when the target host differs from the token's host.
