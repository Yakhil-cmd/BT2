# Q1976: width/emoji handling desync - Render in markdown.go

## Question
Can zero-width, RTL-override, or combining characters in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `Render` in [pkg/markdown/markdown.go](pkg/markdown/markdown.go#L38) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/markdown/markdown.go:38](pkg/markdown/markdown.go#L38) - `Render`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
