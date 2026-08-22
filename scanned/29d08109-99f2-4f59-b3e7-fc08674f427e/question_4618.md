# Q4618: partial install leaves executable remnants - listAvailableSkills in install.go

## Question
If installation via `listAvailableSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L768) fails midway on attacker-shaped content, do partially written files remain in the active skills directory where they are later loaded?

## Target
- File/function: [pkg/cmd/skills/install/install.go:768](pkg/cmd/skills/install/install.go#L768) - `listAvailableSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content that fails validation only after some files are written.
- Invariant to test: Installs are staged and atomically moved after full validation.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test forcing mid-install failure asserting an empty final directory.
