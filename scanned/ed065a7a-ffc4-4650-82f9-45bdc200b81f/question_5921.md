# Q5921: preview renders untrusted skill content - InjectGitHubMetadata in frontmatter.go

## Question
Does `InjectGitHubMetadata` in [internal/skills/frontmatter/frontmatter.go](internal/skills/frontmatter/frontmatter.go#L70) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/frontmatter/frontmatter.go:70](internal/skills/frontmatter/frontmatter.go#L70) - `InjectGitHubMetadata`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
