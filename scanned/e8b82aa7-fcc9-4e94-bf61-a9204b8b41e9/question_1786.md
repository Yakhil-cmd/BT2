# Q1786: discovery walks into attacker-controlled paths - scanAllAgents in update.go

## Question
Can `scanAllAgents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L524) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [pkg/cmd/skills/update/update.go:524](pkg/cmd/skills/update/update.go#L524) - `scanAllAgents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
