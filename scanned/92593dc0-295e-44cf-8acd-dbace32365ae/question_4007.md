# Q4007: width/emoji handling desync - (LiveClient).getTrustDomain in client.go

## Question
Can zero-width, RTL-override, or combining characters in an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims rendered by `getTrustDomain` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L303) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:303](pkg/cmd/attestation/api/client.go#L303) - `(LiveClient).getTrustDomain`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
