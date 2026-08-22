# Q2536: timestamp/expiry checks skipped - NewVerifyCmd in verify.go

## Question
Does `NewVerifyCmd` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L23) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:23](pkg/cmd/attestation/verify/verify.go#L23) - `NewVerifyCmd`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
