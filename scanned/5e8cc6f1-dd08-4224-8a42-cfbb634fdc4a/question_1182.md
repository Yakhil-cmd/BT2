# Q1182: one-of-many bundle passes - DigestAlgForRef in fetch.go

## Question
When several bundles/attestations are supplied to `DigestAlgForRef` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L182), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:182](pkg/cmd/release/shared/fetch.go#L182) - `DigestAlgForRef`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
