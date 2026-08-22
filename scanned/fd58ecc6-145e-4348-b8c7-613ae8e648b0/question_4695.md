# Q4695: timestamp/expiry checks skipped - (LiveSigstoreVerifier).Verify in sigstore.go

## Question
Does `Verify` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L281) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:281](pkg/cmd/attestation/verification/sigstore.go#L281) - `(LiveSigstoreVerifier).Verify`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
