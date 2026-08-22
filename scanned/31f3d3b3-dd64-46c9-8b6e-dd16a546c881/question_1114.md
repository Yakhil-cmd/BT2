# Q1114: artifact read twice from disk - validateSignerWorkflow in policy.go

## Question
Between digest computation and use, does `validateSignerWorkflow` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L149) re-open the artifact path, allowing content substitution by an earlier attacker-triggered write?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:149](pkg/cmd/attestation/verify/policy.go#L149) - `validateSignerWorkflow`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Combine with any write primitive to swap the file after verification.
- Invariant to test: The verified bytes are the bytes returned/used by the caller (single open).
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a single read or an fd-based flow.
