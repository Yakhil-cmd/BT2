# Q4705: policy built from the artifact itself - loadBundleFromJSONFile in attestation.go

## Question
Does `loadBundleFromJSONFile` in [pkg/cmd/attestation/verification/attestation.go](pkg/cmd/attestation/verification/attestation.go#L49) derive any policy field (owner, repo, workflow) from the bundle/artifact under verification instead of from the user's arguments?

## Target
- File/function: [pkg/cmd/attestation/verification/attestation.go:49](pkg/cmd/attestation/verification/attestation.go#L49) - `loadBundleFromJSONFile`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Embed the expected values in the attacker's own bundle.
- Invariant to test: Policy inputs come exclusively from user-provided expectations.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting policy fields are unaffected by bundle contents.
