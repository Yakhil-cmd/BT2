# Q3979: trusted root refreshed from an unverified source - (LiveSigstoreVerifier).chooseVerifier in sigstore.go

## Question
Can `chooseVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L206) be made to load trust material from a path or URL influenced by attacker-published data?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:206](pkg/cmd/attestation/verification/sigstore.go#L206) - `(LiveSigstoreVerifier).chooseVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply trust material through the field that reaches this code.
- Invariant to test: Trust material comes from the embedded root or a verified TUF repository only.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the trust material source is fixed.
