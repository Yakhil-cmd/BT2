# Q4969: ANSI/OSC escape passthrough - fetchExpectedChecksum in copilot.go

## Question
Does `fetchExpectedChecksum` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L342) print server-supplied text (an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:342](pkg/cmd/copilot/copilot.go#L342) - `fetchExpectedChecksum`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh copilot copilot.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
