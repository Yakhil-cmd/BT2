# Q2544: OCI/registry indirection swaps the artifact - verifyAttestations in attestation.go

## Question
For image references handled by `verifyAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L74), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:74](pkg/cmd/attestation/verify/attestation.go#L74) - `verifyAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
