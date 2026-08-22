# Q0304: preview renders untrusted skill content - ResolveRef in discovery.go

## Question
Does `ResolveRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L207) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/discovery/discovery.go:207](internal/skills/discovery/discovery.go#L207) - `ResolveRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
