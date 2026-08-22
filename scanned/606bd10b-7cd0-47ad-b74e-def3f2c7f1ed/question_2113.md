# Q2113: symlink member - downloadCopilot in copilot.go

## Question
Does extraction in `downloadCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L239) honour a member with a symlink mode bit, letting a later member write through it to an arbitrary location?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:239](pkg/cmd/copilot/copilot.go#L239) - `downloadCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Two-entry archive: `link -> ~/.ssh`, then `link/authorized_keys`.
- Invariant to test: Non-regular archive members (symlink, device, hardlink) are skipped or rejected.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a symlink-mode entry asserting it is not created.
