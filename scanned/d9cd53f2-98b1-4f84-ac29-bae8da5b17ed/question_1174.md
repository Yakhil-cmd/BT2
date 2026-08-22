# Q1174: trusted root / TUF fallback - NewCmdVerify in verify.go

## Question
Can `NewCmdVerify` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L40) be pushed onto an embedded, cached, or attacker-served trusted root when the live TUF refresh fails or is stale?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:40](pkg/cmd/release/verify/verify.go#L40) - `NewCmdVerify`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Fail the TUF endpoint for the victim's request and observe which root is used.
- Invariant to test: Trust material is either freshly verified or the operation aborts.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a failing TUF client asserting no fallback acceptance.
