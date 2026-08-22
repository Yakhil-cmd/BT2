# Q3251: error body echoed verbatim - runVerify in verify.go

## Question
Does the error construction in `runVerify` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L264) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:264](pkg/cmd/attestation/verify/verify.go#L264) - `runVerify`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
