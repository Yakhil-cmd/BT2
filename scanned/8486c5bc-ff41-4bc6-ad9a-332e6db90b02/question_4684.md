# Q4684: trusted root refreshed from an unverified source - getAttestations in attestation.go

## Question
Can `getAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L13) be made to load trust material from a path or URL influenced by attacker-published data?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:13](pkg/cmd/attestation/verify/attestation.go#L13) - `getAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply trust material through the field that reaches this code.
- Invariant to test: Trust material comes from the embedded root or a verified TUF repository only.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the trust material source is fixed.
