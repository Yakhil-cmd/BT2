# Q0404: error swallowed into success - (Options).FetchAttestationsFromGitHubAPI in options.go

## Question
Does `FetchAttestationsFromGitHubAPI` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L58) log-and-continue on a verification error (network, TUF refresh, unmarshal), leaving the caller with an apparent pass?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:58](pkg/cmd/attestation/verify/options.go#L58) - `(Options).FetchAttestationsFromGitHubAPI`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Make the trust-material fetch fail for an attacker-timed request.
- Invariant to test: Any verification error is fatal and propagates to the exit code.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Inject an error into each dependency and assert the command fails.
