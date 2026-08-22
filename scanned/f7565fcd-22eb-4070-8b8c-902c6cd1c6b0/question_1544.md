# Q1544: ANSI/OSC escape passthrough - newGitClient in default.go

## Question
Does `newGitClient` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L240) print server-supplied text (a repo/remote/host string or API response field the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/factory/default.go:240](pkg/cmd/factory/default.go#L240) - `newGitClient`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh factory default.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
