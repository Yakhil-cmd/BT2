# Q3853: width/emoji handling desync - printArgs in run.go

## Question
Can zero-width, RTL-override, or combining characters in an extension repository, its release assets, and its manifest fields rendered by `printArgs` in [internal/run/run.go](internal/run/run.go#L91) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [internal/run/run.go:91](internal/run/run.go#L91) - `printArgs`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
