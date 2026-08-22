# Q1687: existing file clobbered - makeSymlink in symlink_other.go

## Question
Does `makeSymlink` in [pkg/cmd/extension/symlink_other.go](pkg/cmd/extension/symlink_other.go#L7) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an extension repository, its release assets, and its manifest fields, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/extension/symlink_other.go:7](pkg/cmd/extension/symlink_other.go#L7) - `makeSymlink`
- Entrypoint: gh extension symlink
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
