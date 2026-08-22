# Q2509: ANSI/OSC escape passthrough - renderSelectedFilePreview in preview.go

## Question
Does `renderSelectedFilePreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L384) print server-supplied text (a published skill's archive entries, frontmatter, and registry metadata) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:384](pkg/cmd/skills/preview/preview.go#L384) - `renderSelectedFilePreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh skills preview.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
