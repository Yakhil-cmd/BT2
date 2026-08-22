# Q2089: ANSI/OSC escape passthrough - NewApp in common.go

## Question
Does `NewApp` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L40) print server-supplied text (codespace/API response fields and everything the codespace-side process sends back) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/codespace/common.go:40](pkg/cmd/codespace/common.go#L40) - `NewApp`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh codespace common.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
