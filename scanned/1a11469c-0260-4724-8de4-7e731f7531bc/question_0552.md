# Q0552: pager/child renderer receives raw bytes - (TablePrinter).AddTimeField in table_printer.go

## Question
Does `AddTimeField` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L26) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [internal/tableprinter/table_printer.go:26](internal/tableprinter/table_printer.go#L26) - `(TablePrinter).AddTimeField`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
