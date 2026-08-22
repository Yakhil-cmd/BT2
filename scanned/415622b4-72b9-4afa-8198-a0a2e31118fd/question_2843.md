# Q2843: ANSI/OSC escape passthrough - getBody in set.go

## Question
Does `getBody` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L413) print server-supplied text (an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/secret/set/set.go:413](pkg/cmd/secret/set/set.go#L413) - `getBody`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh secret set.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
