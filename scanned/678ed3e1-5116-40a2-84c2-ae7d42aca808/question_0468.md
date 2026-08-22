# Q0468: error swallowed into success - DigestAlgForRef in fetch.go

## Question
Does `DigestAlgForRef` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L182) log-and-continue on a verification error (network, TUF refresh, unmarshal), leaving the caller with an apparent pass?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:182](pkg/cmd/release/shared/fetch.go#L182) - `DigestAlgForRef`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make the trust-material fetch fail for an attacker-timed request.
- Invariant to test: Any verification error is fatal and propagates to the exit code.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Inject an error into each dependency and assert the command fails.
