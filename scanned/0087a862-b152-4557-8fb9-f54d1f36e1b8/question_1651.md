# Q1651: deletion of attacker-chosen path - writeManifest in manager.go

## Question
Can an extension repository, its release assets, and its manifest fields steer the cleanup/RemoveAll in `writeManifest` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L394) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/extension/manager.go:394](pkg/cmd/extension/manager.go#L394) - `writeManifest`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
