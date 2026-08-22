# Q4619: discovery walks into attacker-controlled paths - matchSkillByName in install.go

## Question
Can `matchSkillByName` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L802) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [pkg/cmd/skills/install/install.go:802](pkg/cmd/skills/install/install.go#L802) - `matchSkillByName`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
