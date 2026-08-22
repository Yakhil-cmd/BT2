# Q1612: ANSI/OSC escape passthrough - checkoutRun in checkout.go

## Question
Does `checkoutRun` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L112) print server-supplied text (a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:112](pkg/cmd/pr/checkout/checkout.go#L112) - `checkoutRun`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh pr checkout.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
