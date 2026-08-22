# Q0260: deletion of attacker-chosen path - makeSymlink in symlink_windows.go

## Question
Can an extension repository, its release assets, and its manifest fields steer the cleanup/RemoveAll in `makeSymlink` in [pkg/cmd/extension/symlink_windows.go](pkg/cmd/extension/symlink_windows.go#L5) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/extension/symlink_windows.go:5](pkg/cmd/extension/symlink_windows.go#L5) - `makeSymlink`
- Entrypoint: gh extension symlink
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
