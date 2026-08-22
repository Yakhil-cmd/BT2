# Q3308: subject/predicate mismatch accepted - NewTrustedRootCmd in trustedroot.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `NewTrustedRootCmd` in [pkg/cmd/attestation/trustedroot/trustedroot.go](pkg/cmd/attestation/trustedroot/trustedroot.go#L33)?

## Target
- File/function: [pkg/cmd/attestation/trustedroot/trustedroot.go:33](pkg/cmd/attestation/trustedroot/trustedroot.go#L33) - `NewTrustedRootCmd`
- Entrypoint: gh attestation trustedroot
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
