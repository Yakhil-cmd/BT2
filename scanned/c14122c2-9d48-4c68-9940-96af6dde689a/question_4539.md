# Q4539: key collision after normalization - fetchLatestRelease in http.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `fetchLatestRelease` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L119), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/extension/http.go:119](pkg/cmd/extension/http.go#L119) - `fetchLatestRelease`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
