# Q3927: deletion of attacker-chosen path - restoreBackup in update.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata steer the cleanup/RemoveAll in `restoreBackup` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L512) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/skills/update/update.go:512](pkg/cmd/skills/update/update.go#L512) - `restoreBackup`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
