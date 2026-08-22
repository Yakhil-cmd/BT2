# Q2555: subject/predicate mismatch accepted - newCustomVerifier in sigstore.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `newCustomVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L314)?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:314](pkg/cmd/attestation/verification/sigstore.go#L314) - `newCustomVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
