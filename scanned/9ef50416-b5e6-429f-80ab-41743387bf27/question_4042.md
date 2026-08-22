# Q4042: unbounded io.Copy of remote body - fetchReleasePath in fetch.go

## Question
Does `fetchReleasePath` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L281) io.Copy an attacker-sized HTTP body or archive stream into memory or disk without a limit?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:281](pkg/cmd/release/shared/fetch.go#L281) - `fetchReleasePath`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response with no Content-Length and an endless body from a host the victim points gh at.
- Invariant to test: All remote reads are bounded by an explicit limit reader.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an infinite reader asserting the call returns an error after the cap.
