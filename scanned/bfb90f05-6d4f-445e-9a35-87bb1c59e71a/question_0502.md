# Q0502: path from a repo file listing - writeToOutput in read_file.go

## Question
Can repository file paths returned by the API and used in `writeToOutput` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L261) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:261](pkg/cmd/repo/read-file/read_file.go#L261) - `writeToOutput`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
