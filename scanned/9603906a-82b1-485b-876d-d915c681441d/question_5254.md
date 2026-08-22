# Q5254: ANSI/OSC escape passthrough - fetchCommitSHA in http.go

## Question
Does `fetchCommitSHA` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L175) print server-supplied text (an extension repository, its release assets, and its manifest fields) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/extension/http.go:175](pkg/cmd/extension/http.go#L175) - `fetchCommitSHA`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh extension http.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
