# Q0520: concurrent downloads race on paths - processFiles in create.go

## Question
Can multiple entries downloaded concurrently by `processFiles` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L192) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/gist/create/create.go:192](pkg/cmd/gist/create/create.go#L192) - `processFiles`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
