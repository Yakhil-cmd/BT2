# Q5562: ANSI/OSC escape passthrough - printRawIssuePreview in view.go

## Question
Does `printRawIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L197) print server-supplied text (an issue/PR title, body, comment, check output, or release note the attacker authored) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/issue/view/view.go:197](pkg/cmd/issue/view/view.go#L197) - `printRawIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh issue view.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
