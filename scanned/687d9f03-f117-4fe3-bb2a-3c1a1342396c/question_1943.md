# Q1943: path from a repo file listing - getFilesToAdd in edit.go

## Question
Can repository file paths returned by the API and used in `getFilesToAdd` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L420) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:420](pkg/cmd/gist/edit/edit.go#L420) - `getFilesToAdd`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
