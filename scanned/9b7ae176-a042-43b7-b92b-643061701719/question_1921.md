# Q1921: key collision after normalization - jobLogFilenameRegexp in logs.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `jobLogFilenameRegexp` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L266), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/run/view/logs.go:266](pkg/cmd/run/view/logs.go#L266) - `jobLogFilenameRegexp`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
