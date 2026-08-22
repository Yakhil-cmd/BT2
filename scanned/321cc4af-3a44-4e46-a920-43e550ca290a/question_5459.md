# Q5459: release verification trusts the release metadata - (AttestationVerifier).VerifyAttestation in attestation.go

## Question
Does the release-asset verification path in `VerifyAttestation` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L32) take the expected repository/owner from the release object (which an attacker owns for their own release) rather than from the user's expectation?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:32](pkg/cmd/release/shared/attestation.go#L32) - `(AttestationVerifier).VerifyAttestation`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a release in the attacker's repo and attest it there.
- Invariant to test: The expected identity is the user-specified repo, not the release's own.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test verifying an attacker release against a victim-repo expectation asserting failure.
