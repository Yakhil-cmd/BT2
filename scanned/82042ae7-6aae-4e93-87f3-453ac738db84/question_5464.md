# Q5464: empty result treated as success - DigestAlgForRef in fetch.go

## Question
If the attestation list, bundle set, or policy result reaching `DigestAlgForRef` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L182) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:182](pkg/cmd/release/shared/fetch.go#L182) - `DigestAlgForRef`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
