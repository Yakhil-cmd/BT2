# Q4743: OCI/registry indirection swaps the artifact - NewCmdVerify in verify.go

## Question
For image references handled by `NewCmdVerify` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L40), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:40](pkg/cmd/release/verify/verify.go#L40) - `NewCmdVerify`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
