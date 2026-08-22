# Q2618: output directory itself attacker-influenced - checkArchiveTypeOption in download.go

## Question
Can the destination directory used by `checkArchiveTypeOption` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L123) be derived from remote data (run name, artifact name, repo name) rather than from user input?

## Target
- File/function: [pkg/cmd/release/download/download.go:123](pkg/cmd/release/download/download.go#L123) - `checkArchiveTypeOption`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose name becomes the directory and escapes.
- Invariant to test: The destination root comes from the user; remote names contribute only sanitized leaf elements.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the destination root is unchanged by hostile names.
