# Q1117: trusted root / TUF fallback - (Options).Clean in options.go

## Question
Can `Clean` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L50) be pushed onto an embedded, cached, or attacker-served trusted root when the live TUF refresh fails or is stale?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:50](pkg/cmd/attestation/verify/options.go#L50) - `(Options).Clean`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Fail the TUF endpoint for the victim's request and observe which root is used.
- Invariant to test: Trust material is either freshly verified or the operation aborts.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a failing TUF client asserting no fallback acceptance.
