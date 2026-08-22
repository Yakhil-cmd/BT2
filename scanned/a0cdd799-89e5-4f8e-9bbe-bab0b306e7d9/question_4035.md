# Q4035: error body echoed verbatim - FilterAttestationsByFileDigest in attestation.go

## Question
Does the error construction in `FilterAttestationsByFileDigest` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L76) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:76](pkg/cmd/release/shared/attestation.go#L76) - `FilterAttestationsByFileDigest`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
