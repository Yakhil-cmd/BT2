# Q0246: existing file clobbered - (Extension).IsPinned in extension.go

## Question
Does `IsPinned` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L150) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an extension repository, its release assets, and its manifest fields, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/extension/extension.go:150](pkg/cmd/extension/extension.go#L150) - `(Extension).IsPinned`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
