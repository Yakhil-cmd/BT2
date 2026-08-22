# Q0449: artifact read twice from disk - CalculateDigestWithAlgorithm in digest.go

## Question
Between digest computation and use, does `CalculateDigestWithAlgorithm` in [pkg/cmd/attestation/artifact/digest/digest.go](pkg/cmd/attestation/artifact/digest/digest.go#L37) re-open the artifact path, allowing content substitution by an earlier attacker-triggered write?

## Target
- File/function: [pkg/cmd/attestation/artifact/digest/digest.go:37](pkg/cmd/attestation/artifact/digest/digest.go#L37) - `CalculateDigestWithAlgorithm`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Combine with any write primitive to swap the file after verification.
- Invariant to test: The verified bytes are the bytes returned/used by the caller (single open).
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a single read or an fd-based flow.
