# Q5709: key collision after normalization - getStateEntry in update.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `getStateEntry` in [internal/update/update.go](internal/update/update.go#L147), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/update/update.go:147](internal/update/update.go#L147) - `getStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
