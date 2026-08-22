# Q0554: policy fields default to permissive - NewWithWriter in table_printer.go

## Question
Do unset or unparsed policy fields in `NewWithWriter` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L58) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [internal/tableprinter/table_printer.go:58](internal/tableprinter/table_printer.go#L58) - `NewWithWriter`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
