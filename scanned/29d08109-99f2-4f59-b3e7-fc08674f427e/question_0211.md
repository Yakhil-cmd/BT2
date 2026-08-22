# Q0211: ANSI/OSC escape passthrough - printLinkedBranches in develop.go

## Question
Does `printLinkedBranches` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L342) print server-supplied text (a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:342](pkg/cmd/issue/develop/develop.go#L342) - `printLinkedBranches`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh issue develop.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
