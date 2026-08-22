# Q4823: JSON/template output injection - System in iostreams.go

## Question
Can attacker-authored fields exported through `System` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L510) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [pkg/iostreams/iostreams.go:510](pkg/iostreams/iostreams.go#L510) - `System`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
