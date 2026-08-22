# Q1267: unbounded output buffering - New in table_printer.go

## Question
Does `New` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L47) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [internal/tableprinter/table_printer.go:47](internal/tableprinter/table_printer.go#L47) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
