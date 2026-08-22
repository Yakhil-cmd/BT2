# Q4742: unbounded output buffering - verifyAssetRun in verify_asset.go

## Question
Does `verifyAssetRun` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L123) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:123](pkg/cmd/release/verify-asset/verify_asset.go#L123) - `verifyAssetRun`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
