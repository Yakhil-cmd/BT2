# Q4781: path from a repo file listing - extractZipFile in zip.go

## Question
Can repository file paths returned by the API and used in `extractZipFile` in [internal/zip/zip.go](internal/zip/zip.go#L42) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [internal/zip/zip.go:42](internal/zip/zip.go#L42) - `extractZipFile`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
