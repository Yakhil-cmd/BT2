# Q5402: exit code decoupled from verification result - NewLiveSigstoreVerifier in sigstore.go

## Question
Can `NewLiveSigstoreVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L61) print a failure while returning success (or vice versa) for attacker-shaped input, so scripts gating on gh's exit status are fooled?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:61](pkg/cmd/attestation/verification/sigstore.go#L61) - `NewLiveSigstoreVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply input that hits the mismatched branch.
- Invariant to test: Result reporting and exit status derive from one value.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting exit code matches the reported verdict for every branch.
