# Q3257: JSON output shapes a downstream trust decision - getAttestations in attestation.go

## Question
Can attacker-controlled fields in the JSON emitted through `getAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L13) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:13](pkg/cmd/attestation/verify/attestation.go#L13) - `getAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
