# Q3971: timestamp/expiry checks skipped - getAttestations in attestation.go

## Question
Does `getAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L13) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:13](pkg/cmd/attestation/verify/attestation.go#L13) - `getAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
