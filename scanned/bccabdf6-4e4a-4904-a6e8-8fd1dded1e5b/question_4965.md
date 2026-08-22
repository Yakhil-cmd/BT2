# Q4965: existing file clobbered - copilotBinaryPath in copilot.go

## Question
Does `copilotBinaryPath` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L203) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:203](pkg/cmd/copilot/copilot.go#L203) - `copilotBinaryPath`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
