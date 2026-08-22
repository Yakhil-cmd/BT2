# Q4837: very large field stalls or exhausts the client - NewWithWriter in table_printer.go

## Question
Does `NewWithWriter` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L58) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [internal/tableprinter/table_printer.go:58](internal/tableprinter/table_printer.go#L58) - `NewWithWriter`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
