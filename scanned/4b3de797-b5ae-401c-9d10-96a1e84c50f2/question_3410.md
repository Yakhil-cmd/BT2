# Q3410: JSON/template output injection - NewWithWriter in table_printer.go

## Question
Can attacker-authored fields exported through `NewWithWriter` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L58) break out of the JSON/template encoding and inject structure consumed by the user's scripts?

## Target
- File/function: [internal/tableprinter/table_printer.go:58](internal/tableprinter/table_printer.go#L58) - `NewWithWriter`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put quotes, newlines, and template delimiters in a field the attacker owns.
- Invariant to test: All export paths use a real encoder; templates escape values.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Fuzz test comparing decoded output with the input values.
