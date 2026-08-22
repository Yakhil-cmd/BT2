# Q1891: JSON output shapes a downstream trust decision - (AttestationVerifier).VerifyAttestation in attestation.go

## Question
Can attacker-controlled fields in the JSON emitted through `VerifyAttestation` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L32) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:32](pkg/cmd/release/shared/attestation.go#L32) - `(AttestationVerifier).VerifyAttestation`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
