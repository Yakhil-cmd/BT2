# Q1299: JSON/template output injection - parseSection in browse.go

## Question
Can attacker-authored fields exported through `parseSection` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L230) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/cmd/browse/browse.go:230](pkg/cmd/browse/browse.go#L230) - `parseSection`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
