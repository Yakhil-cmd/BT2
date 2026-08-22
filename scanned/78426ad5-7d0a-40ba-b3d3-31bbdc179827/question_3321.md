# Q3321: empty result treated as success - FilterAttestationsByFileDigest in attestation.go

## Question
If the attestation list, bundle set, or policy result reaching `FilterAttestationsByFileDigest` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L76) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:76](pkg/cmd/release/shared/attestation.go#L76) - `FilterAttestationsByFileDigest`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
