# Q1001: key collision after normalization - installSkill in installer.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `installSkill` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L251), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/skills/installer/installer.go:251](internal/skills/installer/installer.go#L251) - `installSkill`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
