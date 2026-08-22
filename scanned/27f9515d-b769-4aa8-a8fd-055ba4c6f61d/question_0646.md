# Q0646: ANSI/OSC escape passthrough - (App).printOpenSSHConfig in ssh.go

## Question
Does `printOpenSSHConfig` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L552) print server-supplied text (codespace/API response fields and everything the codespace-side process sends back) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:552](pkg/cmd/codespace/ssh.go#L552) - `(App).printOpenSSHConfig`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh codespace ssh.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
