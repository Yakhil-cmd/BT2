# Q1931: path from a repo file listing - NewCmdReadDir in read_dir.go

## Question
Can repository file paths returned by the API and used in `NewCmdReadDir` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L44) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:44](pkg/cmd/repo/read-dir/read_dir.go#L44) - `NewCmdReadDir`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
