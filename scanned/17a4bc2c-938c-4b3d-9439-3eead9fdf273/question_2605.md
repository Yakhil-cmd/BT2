# Q2605: timestamp/expiry checks skipped - (AttestationVerifier).VerifyAttestation in attestation.go

## Question
Does `VerifyAttestation` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L32) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:32](pkg/cmd/release/shared/attestation.go#L32) - `(AttestationVerifier).VerifyAttestation`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
