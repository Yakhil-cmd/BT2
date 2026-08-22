# Q3362: concurrent downloads race on paths - writeTable in read_dir.go

## Question
Can multiple entries downloaded concurrently by `writeTable` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L166) resolve to the same path or to each other's directories, producing an unintended final state?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:166](pkg/cmd/repo/read-dir/read_dir.go#L166) - `writeTable`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish entries whose names collide after sanitization.
- Invariant to test: Names are deduplicated deterministically before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test with colliding names asserting deterministic results.
