# Q4741: exit code decoupled from verification result - NewCmdVerifyAsset in verify_asset.go

## Question
Can `NewCmdVerifyAsset` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L38) print a failure while returning success (or vice versa) for attacker-shaped input, so scripts gating on gh's exit status are fooled?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:38](pkg/cmd/release/verify-asset/verify_asset.go#L38) - `NewCmdVerifyAsset`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply input that hits the mismatched branch.
- Invariant to test: Result reporting and exit status derive from one value.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting exit code matches the reported verdict for every branch.
