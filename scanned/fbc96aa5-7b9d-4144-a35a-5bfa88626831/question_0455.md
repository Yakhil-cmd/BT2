# Q0455: timestamp/expiry checks skipped - runDownload in download.go

## Question
Does `runDownload` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L126) accept a bundle whose signing certificate was not valid at signing time, or whose transparency-log inclusion proof is missing or unverified?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:126](pkg/cmd/attestation/download/download.go#L126) - `runDownload`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Present a bundle with a stale or absent inclusion proof.
- Invariant to test: Certificate validity windows and inclusion proofs are mandatory.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a bundle lacking a proof asserting failure.
