# Q2712: JSON/template output injection - issueLabelList in view.go

## Question
Can attacker-authored fields exported through `issueLabelList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L446) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/cmd/issue/view/view.go:446](pkg/cmd/issue/view/view.go#L446) - `issueLabelList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
