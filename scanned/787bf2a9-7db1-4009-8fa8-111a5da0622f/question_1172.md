# Q1172: verify succeeds for an artifact the attacker built - NewCmdVerifyAsset in verify_asset.go

## Question
Can an unprivileged attacker with their own public repository and workflow produce a bundle that satisfies `NewCmdVerifyAsset` in [pkg/cmd/release/verify-asset/verify_asset.go](pkg/cmd/release/verify-asset/verify_asset.go#L38) for a policy the user believes names a different repository or owner?

## Target
- File/function: [pkg/cmd/release/verify-asset/verify_asset.go:38](pkg/cmd/release/verify-asset/verify_asset.go#L38) - `NewCmdVerifyAsset`
- Entrypoint: gh release verify-asset
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Sign the attacker's own artifact through GitHub's own Sigstore instance and craft the claim fields.
- Invariant to test: Every policy predicate (source repo, owner, workflow, issuer, digest) is matched exactly.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a genuine bundle from a different repo asserting failure.
