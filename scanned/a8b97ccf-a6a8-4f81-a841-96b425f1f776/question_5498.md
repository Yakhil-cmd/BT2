# Q5498: existing file clobbered - writeToOutput in read_file.go

## Question
Does `writeToOutput` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L261) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an asset, artifact, gist, or archive-member name and its bytes, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:261](pkg/cmd/repo/read-file/read_file.go#L261) - `writeToOutput`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
