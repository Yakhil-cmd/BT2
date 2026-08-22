# Q1695: ANSI/OSC escape passthrough - NewCmdExtension in extension.go

## Question
Does `NewCmdExtension` in [pkg/cmd/root/extension.go](pkg/cmd/root/extension.go#L22) print server-supplied text (an extension repository, its release assets, and its manifest fields) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/root/extension.go:22](pkg/cmd/root/extension.go#L22) - `NewCmdExtension`
- Entrypoint: gh root extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh root extension.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
