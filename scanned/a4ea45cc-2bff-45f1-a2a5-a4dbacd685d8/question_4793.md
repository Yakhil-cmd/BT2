# Q4793: asset filename controls the write path - PromptGists in shared.go

## Question
Does `PromptGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L228) build the output path from a server-supplied name (asset name, artifact name, gist filename, Content-Disposition) without sanitizing separators and traversal?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:228](pkg/cmd/gist/shared/shared.go#L228) - `PromptGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a release/artifact/gist whose file is named `../../.bashrc` and let the victim run gh gist.
- Invariant to test: Output names are sanitized to a single path element inside the chosen directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile names asserting the resolved output path.
