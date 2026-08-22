# Q1072: preview renders untrusted skill content - scanAllAgents in update.go

## Question
Does `scanAllAgents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L524) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [pkg/cmd/skills/update/update.go:524](pkg/cmd/skills/update/update.go#L524) - `scanAllAgents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
