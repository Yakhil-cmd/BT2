# Q1534: concurrent downloads race on paths - (Absolute).Join in absolute.go

## Question
Can multiple entries downloaded concurrently by `Join` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L38) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [internal/safepaths/absolute.go:38](internal/safepaths/absolute.go#L38) - `(Absolute).Join`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
