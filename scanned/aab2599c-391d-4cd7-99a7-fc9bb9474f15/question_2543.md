# Q2543: exit code decoupled from verification result - getAttestations in attestation.go

## Question
Can `getAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L13) print a failure while returning success (or vice versa) for attacker-shaped input, so scripts gating on gh's exit status are fooled?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:13](pkg/cmd/attestation/verify/attestation.go#L13) - `getAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply input that hits the mismatched branch.
- Invariant to test: Result reporting and exit status derive from one value.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting exit code matches the reported verdict for every branch.
