# Q5312: key collision after normalization - fetchDescription in discovery.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `fetchDescription` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L648), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/skills/discovery/discovery.go:648](internal/skills/discovery/discovery.go#L648) - `fetchDescription`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
