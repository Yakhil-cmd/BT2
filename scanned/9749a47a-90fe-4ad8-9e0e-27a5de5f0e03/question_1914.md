# Q1914: asset filename controls the write path - downloadArtifact in http.go

## Question
Does `downloadArtifact` in [pkg/cmd/run/download/http.go](pkg/cmd/run/download/http.go#L31) build the output path from a server-supplied name (asset name, artifact name, gist filename, Content-Disposition) without sanitizing separators and traversal?

## Target
- File/function: [pkg/cmd/run/download/http.go:31](pkg/cmd/run/download/http.go#L31) - `downloadArtifact`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a release/artifact/gist whose file is named `../../.bashrc` and let the victim run gh run download.
- Invariant to test: Output names are sanitized to a single path element inside the chosen directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile names asserting the resolved output path.
