# Q3427: ANSI/OSC escape passthrough - PrintHeader in display.go

## Question
Does `PrintHeader` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L58) print server-supplied text (an issue/PR title, body, comment, check output, or release note the attacker authored) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:58](pkg/cmd/pr/shared/display.go#L58) - `PrintHeader`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh pr.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
