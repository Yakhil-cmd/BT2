# Q0464: OCI/registry indirection swaps the artifact - FilterAttestationsByTag in attestation.go

## Question
For image references handled by `FilterAttestationsByTag` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L58), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:58](pkg/cmd/release/shared/attestation.go#L58) - `FilterAttestationsByTag`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
