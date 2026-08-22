# Q0231: existing file clobbered - (Manager).UpdateDir in manager.go

## Question
Does `UpdateDir` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L598) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an extension repository, its release assets, and its manifest fields, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/extension/manager.go:598](pkg/cmd/extension/manager.go#L598) - `(Manager).UpdateDir`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
