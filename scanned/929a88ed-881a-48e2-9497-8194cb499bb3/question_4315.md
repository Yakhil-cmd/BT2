# Q4315: existing file clobbered - HomeDirPath in config.go

## Question
Does `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) overwrite an existing file (no O_EXCL / no collision check) when the name comes from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
