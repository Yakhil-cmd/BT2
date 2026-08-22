# Q5501: ANSI/OSC escape passthrough - writeTSV in read_dir.go

## Question
Does `writeTSV` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L154) print server-supplied text (an asset, artifact, gist, or archive-member name and its bytes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:154](pkg/cmd/repo/read-dir/read_dir.go#L154) - `writeTSV`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with gh repo read-dir.
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
