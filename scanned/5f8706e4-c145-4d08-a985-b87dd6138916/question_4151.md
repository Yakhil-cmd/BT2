# Q4151: JSON/template output injection - printSummary in output.go

## Question
Can attacker-authored fields exported through `printSummary` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L69) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:69](pkg/cmd/pr/checks/output.go#L69) - `printSummary`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
