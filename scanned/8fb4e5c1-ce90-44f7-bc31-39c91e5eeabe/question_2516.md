# Q2516: deletion of attacker-chosen path - publishRun in publish.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata steer the cleanup/RemoveAll in `publishRun` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L168) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:168](pkg/cmd/skills/publish/publish.go#L168) - `publishRun`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
