# Q4677: artifact read twice from disk - NewVerifyCmd in verify.go

## Question
Between digest computation and use, does `NewVerifyCmd` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L23) re-open the artifact path, allowing content substitution by an earlier attacker-triggered write?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:23](pkg/cmd/attestation/verify/verify.go#L23) - `NewVerifyCmd`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Combine with any write primitive to swap the file after verification.
- Invariant to test: The verified bytes are the bytes returned/used by the caller (single open).
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a single read or an fd-based flow.
