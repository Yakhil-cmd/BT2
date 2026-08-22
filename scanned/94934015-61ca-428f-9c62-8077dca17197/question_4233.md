# Q4233: prompt text carries attacker content - chooseCodespaceFromList in common.go

## Question
Is remote text (codespace/API response fields and everything the codespace-side process sends back) interpolated into the prompt rendered by `chooseCodespaceFromList` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L93) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/codespace/common.go:93](pkg/cmd/codespace/common.go#L93) - `chooseCodespaceFromList`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
