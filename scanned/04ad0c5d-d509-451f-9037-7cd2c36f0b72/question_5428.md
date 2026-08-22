# Q5428: OCI/registry indirection swaps the artifact - (LiveClient).buildRequestURL in client.go

## Question
For image references handled by `buildRequestURL` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L104), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:104](pkg/cmd/attestation/api/client.go#L104) - `(LiveClient).buildRequestURL`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
