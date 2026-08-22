# Q1032: discovery walks into attacker-controlled paths - DiscoverSkillByPathWithOptions in discovery.go

## Question
Can `DiscoverSkillByPathWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L716) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [internal/skills/discovery/discovery.go:716](internal/skills/discovery/discovery.go#L716) - `DiscoverSkillByPathWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
