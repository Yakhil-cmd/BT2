# Q4775: concurrent downloads race on paths - getJobNameForLogFilename in logs.go

## Question
Can multiple entries downloaded concurrently by `getJobNameForLogFilename` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L246) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/run/view/logs.go:246](pkg/cmd/run/view/logs.go#L246) - `getJobNameForLogFilename`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
