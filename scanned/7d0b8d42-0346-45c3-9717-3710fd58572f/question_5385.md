# Q5385: preview renders untrusted skill content - parseGitHubURL in publish.go

## Question
Does `parseGitHubURL` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1006) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1006](pkg/cmd/skills/publish/publish.go#L1006) - `parseGitHubURL`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
