# Q1201: path from a repo file listing - ListArtifacts in artifacts.go

## Question
Can repository file paths returned by the API and used in `ListArtifacts` in [pkg/cmd/run/shared/artifacts.go](pkg/cmd/run/shared/artifacts.go#L23) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/run/shared/artifacts.go:23](pkg/cmd/run/shared/artifacts.go#L23) - `ListArtifacts`
- Entrypoint: gh run
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
