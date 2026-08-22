# Q3376: path from a repo file listing - processFiles in create.go

## Question
Can repository file paths returned by the API and used in `processFiles` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L192) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/gist/create/create.go:192](pkg/cmd/gist/create/create.go#L192) - `processFiles`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
