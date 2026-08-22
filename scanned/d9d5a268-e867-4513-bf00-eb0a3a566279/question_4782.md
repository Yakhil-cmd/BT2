# Q4782: concurrent downloads race on paths - NewCmdReadFile in read_file.go

## Question
Can multiple entries downloaded concurrently by `NewCmdReadFile` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L51) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:51](pkg/cmd/repo/read-file/read_file.go#L51) - `NewCmdReadFile`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
