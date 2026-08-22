# Q0394: policy built from the artifact itself - NewVerifyCmd in verify.go

## Question
Does `NewVerifyCmd` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L23) derive any policy field (owner, repo, workflow) from the bundle/artifact under verification instead of from the user's arguments?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:23](pkg/cmd/attestation/verify/verify.go#L23) - `NewVerifyCmd`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Embed the expected values in the attacker's own bundle.
- Invariant to test: Policy inputs come exclusively from user-provided expectations.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting policy fields are unaffected by bundle contents.
