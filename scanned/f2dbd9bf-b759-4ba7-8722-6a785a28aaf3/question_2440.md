# Q2440: discovery walks into attacker-controlled paths - acquireFLock in lockfile.go

## Question
Can `acquireFLock` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L155) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:155](internal/skills/lockfile/lockfile.go#L155) - `acquireFLock`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
