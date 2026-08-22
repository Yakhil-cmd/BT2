# Q4569: preview renders untrusted skill content - installLocalSkill in installer.go

## Question
Does `installLocalSkill` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L180) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/installer/installer.go:180](internal/skills/installer/installer.go#L180) - `installLocalSkill`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
