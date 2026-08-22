# Q4653: prompt text carries attacker content - selectSkill in preview.go

## Question
Is remote text (a published skill's archive entries, frontmatter, and registry metadata) interpolated into the prompt rendered by `selectSkill` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L453) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:453](pkg/cmd/skills/preview/preview.go#L453) - `selectSkill`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
