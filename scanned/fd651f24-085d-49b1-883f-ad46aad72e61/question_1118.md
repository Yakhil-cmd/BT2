# Q1118: one-of-many bundle passes - (Options).FetchAttestationsFromGitHubAPI in options.go

## Question
When several bundles/attestations are supplied to `FetchAttestationsFromGitHubAPI` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L58), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:58](pkg/cmd/attestation/verify/options.go#L58) - `(Options).FetchAttestationsFromGitHubAPI`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
