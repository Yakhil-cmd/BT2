# Q2502: discovery walks into attacker-controlled paths - parseInstalledSkill in update.go

## Question
Can `parseInstalledSkill` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L601) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [pkg/cmd/skills/update/update.go:601](pkg/cmd/skills/update/update.go#L601) - `parseInstalledSkill`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
