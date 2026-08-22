# Q1970: width/emoji handling desync - BinaryContentType in content.go

## Question
Can zero-width, RTL-override, or combining characters in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `BinaryContentType` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L24) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/iostreams/content.go:24](pkg/iostreams/content.go#L24) - `BinaryContentType`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
