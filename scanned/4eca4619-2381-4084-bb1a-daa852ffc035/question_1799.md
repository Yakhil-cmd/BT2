# Q1799: preview renders untrusted skill content - buildTree in preview.go

## Question
Does `buildTree` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L501) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:501](pkg/cmd/skills/preview/preview.go#L501) - `buildTree`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
