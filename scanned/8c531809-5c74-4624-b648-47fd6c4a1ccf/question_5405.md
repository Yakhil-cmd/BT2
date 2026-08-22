# Q5405: artifact read twice from disk - (LiveSigstoreVerifier).chooseVerifier in sigstore.go

## Question
Between digest computation and use, does `chooseVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L206) re-open the artifact path, allowing content substitution by an earlier attacker-triggered write?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:206](pkg/cmd/attestation/verification/sigstore.go#L206) - `(LiveSigstoreVerifier).chooseVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Combine with any write primitive to swap the file after verification.
- Invariant to test: The verified bytes are the bytes returned/used by the caller (single open).
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a single read or an fd-based flow.
