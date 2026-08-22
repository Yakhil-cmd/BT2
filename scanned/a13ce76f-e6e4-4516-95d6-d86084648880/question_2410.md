# Q2410: trusted root / TUF fallback - NewCmdRoot in root.go

## Question
Can `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64) be pushed onto an embedded, cached, or attacker-served trusted root when the live TUF refresh fails or is stale?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Fail the TUF endpoint for the victim's request and observe which root is used.
- Invariant to test: Trust material is either freshly verified or the operation aborts.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a failing TUF client asserting no fallback acceptance.
