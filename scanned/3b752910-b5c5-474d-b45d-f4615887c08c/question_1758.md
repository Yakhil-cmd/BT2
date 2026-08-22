# Q1758: prompt text carries attacker content - resolveRepoArg in install.go

## Question
Is remote text (a published skill's archive entries, frontmatter, and registry metadata) interpolated into the prompt rendered by `resolveRepoArg` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L580) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/skills/install/install.go:580](pkg/cmd/skills/install/install.go#L580) - `resolveRepoArg`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
