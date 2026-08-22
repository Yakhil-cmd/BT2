# Q4796: width/emoji handling desync - editRun in edit.go

## Question
Can zero-width, RTL-override, or combining characters in an asset, artifact, gist, or archive-member name and its bytes rendered by `editRun` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L118) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:118](pkg/cmd/gist/edit/edit.go#L118) - `editRun`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
