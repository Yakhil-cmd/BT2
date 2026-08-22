# Q2627: path from a repo file listing - isolateArtifacts in download.go

## Question
Can repository file paths returned by the API and used in `isolateArtifacts` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L205) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/run/download/download.go:205](pkg/cmd/run/download/download.go#L205) - `isolateArtifacts`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
