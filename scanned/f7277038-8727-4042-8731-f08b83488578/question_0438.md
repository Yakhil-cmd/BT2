# Q0438: policy built from the artifact itself - FilterAttestations in attestation.go

## Question
Does `FilterAttestations` in [pkg/cmd/attestation/api/attestation.go](pkg/cmd/attestation/api/attestation.go#L27) derive any policy field (owner, repo, workflow) from the bundle/artifact under verification instead of from the user's arguments?

## Target
- File/function: [pkg/cmd/attestation/api/attestation.go:27](pkg/cmd/attestation/api/attestation.go#L27) - `FilterAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Embed the expected values in the attacker's own bundle.
- Invariant to test: Policy inputs come exclusively from user-provided expectations.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting policy fields are unaffected by bundle contents.
