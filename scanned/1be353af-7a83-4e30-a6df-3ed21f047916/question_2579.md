# Q2579: error swallowed into success - (LiveClient).getTrustDomain in client.go

## Question
Does `getTrustDomain` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L303) log-and-continue on a verification error (network, TUF refresh, unmarshal), leaving the caller with an apparent pass?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:303](pkg/cmd/attestation/api/client.go#L303) - `(LiveClient).getTrustDomain`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Make the trust-material fetch fail for an attacker-timed request.
- Invariant to test: Any verification error is fatal and propagates to the exit code.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Inject an error into each dependency and assert the command fails.
