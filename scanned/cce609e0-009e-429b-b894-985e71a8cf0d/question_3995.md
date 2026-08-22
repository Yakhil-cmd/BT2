# Q3995: policy built from the artifact itself - VerifyCertExtensions in extensions.go

## Question
Does `VerifyCertExtensions` in [pkg/cmd/attestation/verification/extensions.go](pkg/cmd/attestation/verification/extensions.go#L17) derive any policy field (owner, repo, workflow) from the bundle/artifact under verification instead of from the user's arguments?

## Target
- File/function: [pkg/cmd/attestation/verification/extensions.go:17](pkg/cmd/attestation/verification/extensions.go#L17) - `VerifyCertExtensions`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Embed the expected values in the attacker's own bundle.
- Invariant to test: Policy inputs come exclusively from user-provided expectations.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting policy fields are unaffected by bundle contents.
