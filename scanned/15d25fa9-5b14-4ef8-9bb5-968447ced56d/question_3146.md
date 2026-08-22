# Q3146: discovery walks into attacker-controlled paths - (AgentHost).InstallDir in registry.go

## Question
Can `InstallDir` in [internal/skills/registry/registry.go](internal/skills/registry/registry.go#L410) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [internal/skills/registry/registry.go:410](internal/skills/registry/registry.go#L410) - `(AgentHost).InstallDir`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
