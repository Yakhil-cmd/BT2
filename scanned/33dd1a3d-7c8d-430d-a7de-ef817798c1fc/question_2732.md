# Q2732: token leaked into child env/argv - Copy in ssh.go

## Question
Does `Copy` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L42) pass the active GitHub token via argv or an inherited environment into a process whose identity is influenced by codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/ssh.go:42](internal/codespaces/ssh.go#L42) - `Copy`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Get gh to spawn a helper for an attacker-controlled host/extension and read the token from its own environment or /proc argv.
- Invariant to test: The token is only passed to processes bound to the host it authenticates.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Assert the env/argv captured by a stub runner contains no token when the target host differs from the token's host.
