# Q2658: concurrent downloads race on paths - NewCmdView in view.go

## Question
Can multiple entries downloaded concurrently by `NewCmdView` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L42) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/gist/view/view.go:42](pkg/cmd/gist/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
