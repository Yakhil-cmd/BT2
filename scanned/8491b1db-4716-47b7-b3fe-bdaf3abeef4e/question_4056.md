# Q4056: concurrent downloads race on paths - downloadArtifact in http.go

## Question
Can multiple entries downloaded concurrently by `downloadArtifact` in [pkg/cmd/run/download/http.go](pkg/cmd/run/download/http.go#L31) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/run/download/http.go:31](pkg/cmd/run/download/http.go#L31) - `downloadArtifact`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
