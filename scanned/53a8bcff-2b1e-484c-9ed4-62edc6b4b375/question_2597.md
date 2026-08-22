# Q2597: artifact read twice from disk - runDownload in download.go

## Question
Between digest computation and use, does `runDownload` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L126) re-open the artifact path, allowing content substitution by an earlier attacker-triggered write?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:126](pkg/cmd/attestation/download/download.go#L126) - `runDownload`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Combine with any write primitive to swap the file after verification.
- Invariant to test: The verified bytes are the bytes returned/used by the caller (single open).
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a single read or an fd-based flow.
