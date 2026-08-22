# Q1079: prompt text carries attacker content - renderInteractive in preview.go

## Question
Is remote text (a published skill's archive entries, frontmatter, and registry metadata) interpolated into the prompt rendered by `renderInteractive` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L318) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:318](pkg/cmd/skills/preview/preview.go#L318) - `renderInteractive`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
