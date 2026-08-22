# Q0553: width/emoji handling desync - New in table_printer.go

## Question
Can zero-width, RTL-override, or combining characters in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `New` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L47) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [internal/tableprinter/table_printer.go:47](internal/tableprinter/table_printer.go#L47) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
