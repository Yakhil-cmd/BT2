# Q3896: preview renders untrusted skill content - FindNameCollisions in collisions.go

## Question
Does `FindNameCollisions` in [internal/skills/discovery/collisions.go](internal/skills/discovery/collisions.go#L21) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/discovery/collisions.go:21](internal/skills/discovery/collisions.go#L21) - `FindNameCollisions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
