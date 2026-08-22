# Q2460: partial install leaves executable remnants - DiscoverSkillByPathWithOptions in discovery.go

## Question
If installation via `DiscoverSkillByPathWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L716) fails midway on attacker-shaped content, do partially written files remain in the active skills directory where they are later loaded?

## Target
- File/function: [internal/skills/discovery/discovery.go:716](internal/skills/discovery/discovery.go#L716) - `DiscoverSkillByPathWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content that fails validation only after some files are written.
- Invariant to test: Installs are staged and atomically moved after full validation.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test forcing mid-install failure asserting an empty final directory.
