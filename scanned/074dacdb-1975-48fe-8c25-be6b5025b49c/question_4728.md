# Q4728: empty result treated as success - digestLocalFileArtifact in file.go

## Question
If the attestation list, bundle set, or policy result reaching `digestLocalFileArtifact` in [pkg/cmd/attestation/artifact/file.go](pkg/cmd/attestation/artifact/file.go#L10) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/attestation/artifact/file.go:10](pkg/cmd/attestation/artifact/file.go#L10) - `digestLocalFileArtifact`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
