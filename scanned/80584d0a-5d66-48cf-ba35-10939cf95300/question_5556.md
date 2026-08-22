# Q5556: JSON/template output injection - parseReviewers in view.go

## Question
Can attacker-authored fields exported through `parseReviewers` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L349) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/cmd/pr/view/view.go:349](pkg/cmd/pr/view/view.go#L349) - `parseReviewers`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
