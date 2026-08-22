# Q0239: token leaked into child env/argv - codesignBinary in manager.go

## Question
Does `codesignBinary` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L854) pass the active GitHub token via argv or an inherited environment into a process whose identity is influenced by an extension repository, its release assets, and its manifest fields?

## Target
- File/function: [pkg/cmd/extension/manager.go:854](pkg/cmd/extension/manager.go#L854) - `codesignBinary`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Get gh to spawn a helper for an attacker-controlled host/extension and read the token from its own environment or /proc argv.
- Invariant to test: The token is only passed to processes bound to the host it authenticates.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Assert the env/argv captured by a stub runner contains no token when the target host differs from the token's host.
