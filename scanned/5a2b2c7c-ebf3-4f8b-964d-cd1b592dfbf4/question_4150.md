# Q4150: very large field stalls or exhausts the client - addRow in output.go

## Question
Does `addRow` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L11) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:11](pkg/cmd/pr/checks/output.go#L11) - `addRow`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
