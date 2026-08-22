# Q1869: error swallowed into success - NewDigestedArtifact in artifact.go

## Question
Does `NewDigestedArtifact` in [pkg/cmd/attestation/artifact/artifact.go](pkg/cmd/attestation/artifact/artifact.go#L64) log-and-continue on a verification error (network, TUF refresh, unmarshal), leaving the caller with an apparent pass?

## Target
- File/function: [pkg/cmd/attestation/artifact/artifact.go:64](pkg/cmd/attestation/artifact/artifact.go#L64) - `NewDigestedArtifact`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Make the trust-material fetch fail for an attacker-timed request.
- Invariant to test: Any verification error is fatal and propagates to the exit code.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Inject an error into each dependency and assert the command fails.
