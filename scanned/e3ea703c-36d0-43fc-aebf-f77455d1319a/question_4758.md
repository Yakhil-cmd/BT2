# Q4758: duplicate entry overwrite - NewCmdDownload in download.go

## Question
Can duplicate member names in an archive processed by `NewCmdDownload` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L46) let a second entry silently replace an already-validated first entry?

## Target
- File/function: [pkg/cmd/release/download/download.go:46](pkg/cmd/release/download/download.go#L46) - `NewCmdDownload`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an archive where the same path appears twice with different content.
- Invariant to test: Duplicate member names are rejected before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a duplicated entry asserting an error.
