# Q3309: OCI/registry indirection swaps the artifact - getTrustedRoot in trustedroot.go

## Question
For image references handled by `getTrustedRoot` in [pkg/cmd/attestation/trustedroot/trustedroot.go](pkg/cmd/attestation/trustedroot/trustedroot.go#L125), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/trustedroot/trustedroot.go:125](pkg/cmd/attestation/trustedroot/trustedroot.go#L125) - `getTrustedRoot`
- Entrypoint: gh attestation trustedroot
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
