# Q3322: one-of-many bundle passes - buildVerificationPolicy in attestation.go

## Question
When several bundles/attestations are supplied to `buildVerificationPolicy` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L102), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:102](pkg/cmd/release/shared/attestation.go#L102) - `buildVerificationPolicy`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
