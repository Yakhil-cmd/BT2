# Q0469: path from a repo file listing - FetchRelease in fetch.go

## Question
Can repository file paths returned by the API and used in `FetchRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L192) contain traversal or absolute components that escape the output directory?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:192](pkg/cmd/release/shared/fetch.go#L192) - `FetchRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo/tree whose entry path escapes.
- Invariant to test: API-provided paths are validated exactly like archive members.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile tree paths.
