# Q5458: width/emoji handling desync - printVerifiedSubjects in verify.go

## Question
Can zero-width, RTL-override, or combining characters in an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims rendered by `printVerifiedSubjects` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L196) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:196](pkg/cmd/release/verify/verify.go#L196) - `printVerifiedSubjects`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
