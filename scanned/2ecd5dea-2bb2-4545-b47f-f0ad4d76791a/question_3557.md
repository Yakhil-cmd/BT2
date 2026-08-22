# Q3557: prompt text carries attacker content - getBody in set.go

## Question
Is remote text (an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes) interpolated into the prompt rendered by `getBody` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L413) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/secret/set/set.go:413](pkg/cmd/secret/set/set.go#L413) - `getBody`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
