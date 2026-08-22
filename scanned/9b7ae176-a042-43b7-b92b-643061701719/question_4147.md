# Q4147: JSON/template output injection - formatComment in comments.go

## Question
Can attacker-authored fields exported through `formatComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L89) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:89](pkg/cmd/pr/shared/comments.go#L89) - `formatComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
