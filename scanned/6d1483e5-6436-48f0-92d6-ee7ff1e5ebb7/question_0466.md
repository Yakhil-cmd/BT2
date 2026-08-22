# Q0466: subject/predicate mismatch accepted - buildVerificationPolicy in attestation.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `buildVerificationPolicy` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L102)?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:102](pkg/cmd/release/shared/attestation.go#L102) - `buildVerificationPolicy`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
