# Q2569: timestamp/expiry checks skipped - DefaultOptionsWithCacheSetting in tuf.go

## Question
Does `DefaultOptionsWithCacheSetting` in [pkg/cmd/attestation/verification/tuf.go](pkg/cmd/attestation/verification/tuf.go#L21) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/attestation/verification/tuf.go:21](pkg/cmd/attestation/verification/tuf.go#L21) - `DefaultOptionsWithCacheSetting`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
