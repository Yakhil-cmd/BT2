# Q5417: trusted root / TUF fallback - GetLocalAttestations in attestation.go

## Question
Can `GetLocalAttestations` in [pkg/cmd/attestation/verification/attestation.go](pkg/cmd/attestation/verification/attestation.go#L24) be pushed onto an embedded, cached, or attacker-served trusted root when the live TUF refresh fails or is stale?

## Target
- File/function: [pkg/cmd/attestation/verification/attestation.go:24](pkg/cmd/attestation/verification/attestation.go#L24) - `GetLocalAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Fail the TUF endpoint for the victim's request and observe which root is used.
- Invariant to test: Trust material is either freshly verified or the operation aborts.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a failing TUF client asserting no fallback acceptance.
