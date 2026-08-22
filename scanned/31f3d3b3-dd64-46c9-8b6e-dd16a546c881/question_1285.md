# Q1285: width/emoji handling desync - PrintHeader in display.go

## Question
Can zero-width, RTL-override, or combining characters in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `PrintHeader` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L58) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:58](pkg/cmd/pr/shared/display.go#L58) - `PrintHeader`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
