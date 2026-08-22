# Q1251: existing file clobbered - (IOStreams).TempFile in iostreams.go

## Question
Does `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) overwrite an existing file (no O_EXCL / no collision check) when the name comes from an issue/PR title, body, comment, check output, or release note the attacker authored, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
