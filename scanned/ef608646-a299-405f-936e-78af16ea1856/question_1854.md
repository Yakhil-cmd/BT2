# Q1854: OCI/registry indirection swaps the artifact - verifyCertExtensions in extensions.go

## Question
For image references handled by `verifyCertExtensions` in [pkg/cmd/attestation/verification/extensions.go](pkg/cmd/attestation/verification/extensions.go#L43), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/verification/extensions.go:43](pkg/cmd/attestation/verification/extensions.go#L43) - `verifyCertExtensions`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
