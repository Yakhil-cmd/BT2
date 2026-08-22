# Q4123: prompt/output spoofing with CR and newline - New in table_printer.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `New` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L47) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [internal/tableprinter/table_printer.go:47](internal/tableprinter/table_printer.go#L47) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
