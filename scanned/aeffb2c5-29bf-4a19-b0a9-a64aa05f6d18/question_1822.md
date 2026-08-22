# Q1822: JSON output shapes a downstream trust decision - NewVerifyCmd in verify.go

## Question
Can attacker-controlled fields in the JSON emitted through `NewVerifyCmd` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L23) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:23](pkg/cmd/attestation/verify/verify.go#L23) - `NewVerifyCmd`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
