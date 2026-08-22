# Q3846: existing file clobbered - checkForUpdate in cmd.go

## Question
Does `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an extension repository, its release assets, and its manifest fields, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
