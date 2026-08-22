# Q0268: one-of-many bundle passes - NewCmdRoot in root.go

## Question
When several bundles/attestations are supplied to `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
