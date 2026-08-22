# Q5471: unbounded io.Copy of remote body - NewCmdDownload in download.go

## Question
Does `NewCmdDownload` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L46) io.Copy an attacker-sized HTTP body or archive stream into memory or disk without a limit?

## Target
- File/function: [pkg/cmd/release/download/download.go:46](pkg/cmd/release/download/download.go#L46) - `NewCmdDownload`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response with no Content-Length and an endless body from a host the victim points gh at.
- Invariant to test: All remote reads are bounded by an explicit limit reader.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an infinite reader asserting the call returns an error after the cap.
