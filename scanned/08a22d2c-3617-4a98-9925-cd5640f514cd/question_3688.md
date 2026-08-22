# Q3688: prompt text carries attacker content - newPrompter in default.go

## Question
Is remote text (a repo/remote/host string or API response field the attacker publishes) interpolated into the prompt rendered by `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
