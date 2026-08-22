# Q5515: width/emoji handling desync - createRun in create.go

## Question
Can zero-width, RTL-override, or combining characters in an asset, artifact, gist, or archive-member name and its bytes rendered by `createRun` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L108) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/gist/create/create.go:108](pkg/cmd/gist/create/create.go#L108) - `createRun`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
