# Q2473: ANSI/OSC escape passthrough - resolveVersion in install.go

## Question
Does `resolveVersion` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L623) print server-supplied text (a published skill's archive entries, frontmatter, and registry metadata) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/skills/install/install.go:623](pkg/cmd/skills/install/install.go#L623) - `resolveVersion`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh skills install.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
