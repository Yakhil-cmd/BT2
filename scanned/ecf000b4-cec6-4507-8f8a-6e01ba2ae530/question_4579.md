# Q4579: key collision after normalization - readFrom in lockfile.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `readFrom` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L53), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:53](internal/skills/lockfile/lockfile.go#L53) - `readFrom`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
