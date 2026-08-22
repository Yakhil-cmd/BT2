# Q4052: path from a repo file listing - isWindowsReservedFilename in download.go

## Question
Can repository file paths returned by the API and used in `isWindowsReservedFilename` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L456) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/release/download/download.go:456](pkg/cmd/release/download/download.go#L456) - `isWindowsReservedFilename`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
