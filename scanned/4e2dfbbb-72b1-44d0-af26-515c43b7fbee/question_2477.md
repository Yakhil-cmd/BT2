# Q2477: preview renders untrusted skill content - listAvailableSkills in install.go

## Question
Does `listAvailableSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L768) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [pkg/cmd/skills/install/install.go:768](pkg/cmd/skills/install/install.go#L768) - `listAvailableSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
