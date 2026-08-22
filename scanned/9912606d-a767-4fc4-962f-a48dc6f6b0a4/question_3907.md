# Q3907: prompt text carries attacker content - skillSearchFunc in install.go

## Question
Is remote text (a published skill's archive entries, frontmatter, and registry metadata) interpolated into the prompt rendered by `skillSearchFunc` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L844) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/skills/install/install.go:844](pkg/cmd/skills/install/install.go#L844) - `skillSearchFunc`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
