# Q0431: one-of-many bundle passes - (LiveClient).GetByDigest in client.go

## Question
When several bundles/attestations are supplied to `GetByDigest` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L89), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:89](pkg/cmd/attestation/api/client.go#L89) - `(LiveClient).GetByDigest`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
