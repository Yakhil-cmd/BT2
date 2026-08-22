# Q0967: width/emoji handling desync - repoExists in http.go

## Question
Can zero-width, RTL-override, or combining characters in an extension repository, its release assets, and its manifest fields rendered by `repoExists` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L16) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/extension/http.go:16](pkg/cmd/extension/http.go#L16) - `repoExists`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
