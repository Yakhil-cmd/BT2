# Q2101: key collision after normalization - ParseSessionIDFromURL in capi.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `ParseSessionIDFromURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L78), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:78](pkg/cmd/agent-task/shared/capi.go#L78) - `ParseSessionIDFromURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
