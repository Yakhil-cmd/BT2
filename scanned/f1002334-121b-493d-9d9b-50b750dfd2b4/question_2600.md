# Q2600: OCI/registry indirection swaps the artifact - NewCmdVerifyAsset in verify_asset.go

## Question
For image references handled by `NewCmdVerifyAsset` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L38), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:38](pkg/cmd/release/verify-asset/verify_asset.go#L38) - `NewCmdVerifyAsset`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
