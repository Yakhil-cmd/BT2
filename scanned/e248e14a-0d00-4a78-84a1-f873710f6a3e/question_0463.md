# Q0463: policy built from the artifact itself - (AttestationVerifier).VerifyAttestation in attestation.go

## Question
Does `VerifyAttestation` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L32) derive any policy field (owner, repo, workflow) from the bundle/artifact under verification instead of from the user's arguments?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:32](pkg/cmd/release/shared/attestation.go#L32) - `(AttestationVerifier).VerifyAttestation`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Embed the expected values in the attacker's own bundle.
- Invariant to test: Policy inputs come exclusively from user-provided expectations.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting policy fields are unaffected by bundle contents.
