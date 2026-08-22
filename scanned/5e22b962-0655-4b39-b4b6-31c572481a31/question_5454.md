# Q5454: JSON output shapes a downstream trust decision - NewCmdVerifyAsset in verify_asset.go

## Question
Can attacker-controlled fields in the JSON emitted through `NewCmdVerifyAsset` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L38) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:38](pkg/cmd/release/verify-asset/verify_asset.go#L38) - `NewCmdVerifyAsset`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
