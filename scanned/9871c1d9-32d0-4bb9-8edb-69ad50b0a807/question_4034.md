# Q4034: timestamp/expiry checks skipped - FilterAttestationsByTag in attestation.go

## Question
Does `FilterAttestationsByTag` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L58) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:58](pkg/cmd/release/shared/attestation.go#L58) - `FilterAttestationsByTag`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
