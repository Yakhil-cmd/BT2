# Q5400: empty result treated as success - (Options).FetchAttestationsFromGitHubAPI in options.go

## Question
If the attestation list, bundle set, or policy result reaching `FetchAttestationsFromGitHubAPI` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L58) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:58](pkg/cmd/attestation/verify/options.go#L58) - `(Options).FetchAttestationsFromGitHubAPI`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
