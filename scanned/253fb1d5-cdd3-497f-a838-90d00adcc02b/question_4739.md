# Q4739: OCI/registry indirection swaps the artifact - getOrgAndRepo in bundle.go

## Question
For image references handled by `getOrgAndRepo` in [pkg/cmd/attestation/inspect/bundle.go](pkg/cmd/attestation/inspect/bundle.go#L57), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/inspect/bundle.go:57](pkg/cmd/attestation/inspect/bundle.go#L57) - `getOrgAndRepo`
- Entrypoint: gh attestation inspect
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
