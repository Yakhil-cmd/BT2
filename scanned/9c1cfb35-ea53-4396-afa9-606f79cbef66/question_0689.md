# Q0689: deletion of attacker-chosen path - extractFile in copilot.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes steer the cleanup/RemoveAll in `extractFile` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L454) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:454](pkg/cmd/copilot/copilot.go#L454) - `extractFile`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
