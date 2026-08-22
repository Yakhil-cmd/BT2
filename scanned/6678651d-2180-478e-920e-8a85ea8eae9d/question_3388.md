# Q3388: width/emoji handling desync - (IOStreams).startTextualProgressIndicator in iostreams.go

## Question
Can zero-width, RTL-override, or combining characters in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `startTextualProgressIndicator` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L342) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/iostreams/iostreams.go:342](pkg/iostreams/iostreams.go#L342) - `(IOStreams).startTextualProgressIndicator`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
