# Q0843: key collision after normalization - parseErrorResponse in api.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `parseErrorResponse` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L651), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/api/api.go:651](pkg/cmd/api/api.go#L651) - `parseErrorResponse`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
