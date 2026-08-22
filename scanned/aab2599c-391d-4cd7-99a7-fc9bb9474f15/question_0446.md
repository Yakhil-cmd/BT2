# Q0446: empty result treated as success - digestContainerImageArtifact in image.go

## Question
If the attestation list, bundle set, or policy result reaching `digestContainerImageArtifact` in [pkg/cmd/attestation/artifact/image.go](pkg/cmd/attestation/artifact/image.go#L10) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/attestation/artifact/image.go:10](pkg/cmd/attestation/artifact/image.go#L10) - `digestContainerImageArtifact`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
