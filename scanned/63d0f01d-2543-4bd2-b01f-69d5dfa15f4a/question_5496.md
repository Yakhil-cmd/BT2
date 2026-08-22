# Q5496: width/emoji handling desync - readFileRun in read_file.go

## Question
Can zero-width, RTL-override, or combining characters in an asset, artifact, gist, or archive-member name and its bytes rendered by `readFileRun` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L128) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:128](pkg/cmd/repo/read-file/read_file.go#L128) - `readFileRun`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
