# Q0819: existing file clobbered - ParseAbsolute in absolute.go

## Question
Does `ParseAbsolute` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L17) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an asset, artifact, gist, or archive-member name and its bytes, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [internal/safepaths/absolute.go:17](internal/safepaths/absolute.go#L17) - `ParseAbsolute`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
