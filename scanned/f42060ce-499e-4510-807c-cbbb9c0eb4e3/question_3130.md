# Q3130: width/emoji handling desync - printError in cmd.go

## Question
Can zero-width, RTL-override, or combining characters in an extension repository, its release assets, and its manifest fields rendered by `printError` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L282) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [internal/ghcmd/cmd.go:282](internal/ghcmd/cmd.go#L282) - `printError`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
