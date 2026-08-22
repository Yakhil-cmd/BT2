# Q2515: key collision after normalization - NewCmdPublish in publish.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `NewCmdPublish` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L91), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:91](pkg/cmd/skills/publish/publish.go#L91) - `NewCmdPublish`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
