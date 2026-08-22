# Q1837: exit code decoupled from verification result - (LiveSigstoreVerifier).chooseVerifier in sigstore.go

## Question
Can `chooseVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L206) print a failure while returning success (or vice versa) for attacker-shaped input, so scripts gating on gh's exit status are fooled?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:206](pkg/cmd/attestation/verification/sigstore.go#L206) - `(LiveSigstoreVerifier).chooseVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply input that hits the mismatched branch.
- Invariant to test: Result reporting and exit status derive from one value.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting exit code matches the reported verdict for every branch.
