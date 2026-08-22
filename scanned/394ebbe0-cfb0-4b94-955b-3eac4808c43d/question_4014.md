# Q4014: empty result treated as success - (DigestedArtifact).DigestWithAlg in artifact.go

## Question
If the attestation list, bundle set, or policy result reaching `DigestWithAlg` in [pkg/cmd/attestation/artifact/artifact.go](pkg/cmd/attestation/artifact/artifact.go#L87) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/attestation/artifact/artifact.go:87](pkg/cmd/attestation/artifact/artifact.go#L87) - `(DigestedArtifact).DigestWithAlg`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
