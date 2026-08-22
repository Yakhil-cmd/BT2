# Q2601: width/emoji handling desync - verifyAssetRun in verify_asset.go

## Question
Can zero-width, RTL-override, or combining characters in an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims rendered by `verifyAssetRun` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L123) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:123](pkg/cmd/release/verify-asset/verify_asset.go#L123) - `verifyAssetRun`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
