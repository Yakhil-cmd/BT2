# Q2432: preview renders untrusted skill content - (AgentHost).InstallDir in registry.go

## Question
Does `InstallDir` in [internal/skills/registry/registry.go](internal/skills/registry/registry.go#L410) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/registry/registry.go:410](internal/skills/registry/registry.go#L410) - `(AgentHost).InstallDir`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
