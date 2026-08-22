# Q5408: trusted root refreshed from an unverified source - (LiveSigstoreVerifier).Verify in sigstore.go

## Question
Can `Verify` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L281) be made to load trust material from a path or URL influenced by attacker-published data?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:281](pkg/cmd/attestation/verification/sigstore.go#L281) - `(LiveSigstoreVerifier).Verify`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply trust material through the field that reaches this code.
- Invariant to test: Trust material comes from the embedded root or a verified TUF repository only.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the trust material source is fixed.
